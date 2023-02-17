package controller

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nextdotid/proof_server/common"
	"github.com/nextdotid/proof_server/model"
	"github.com/nextdotid/proof_server/types"
	"github.com/nextdotid/proof_server/util/sqs"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

const (
	PER_PAGE = 20
)

type ProofQueryRequest struct {
	Platform   string   `form:"platform"`
	Identity   []string `form:"identity"`
	Page       int      `form:"page"`
	ExactMatch bool     `form:"exact"`
	SortBy     string   `form:"sort"`
	Order      string   `form:"order"`
}

type ProofQueryResponse struct {
	Pagination ProofQueryPaginationResponse `json:"pagination"`
	IDs        []ProofQueryResponseSingle   `json:"ids"`
}

type ProofQueryPaginationResponse struct {
	Total   int64 `json:"total"`
	Per     int   `json:"per"`
	Current int   `json:"current"`
	Next    int   `json:"next"`
}

type ProofQueryResponseSingle struct {
	Persona       string                          `json:"persona"`
	Avatar        string                          `json:"avatar"`
	LastArweaveID string                          `json:"last_arweave_id"`
	ActivatedAt   string                          `json:"activated_at"`
	Proofs        []ProofQueryResponseSingleProof `json:"proofs"`
}

type ProofQueryResponseSingleProof struct {
	Platform      types.Platform `json:"platform"`
	Identity      string         `json:"identity"`
	AltID         string         `json:"alt_id"`
	CreatedAt     string         `json:"created_at"`
	LastCheckedAt string         `json:"last_checked_at"`
	IsValid       bool           `json:"is_valid"`
	InvalidReason string         `json:"invalid_reason"`
}

func proofQuery(c *gin.Context) {
	req := ProofQueryRequest{}
	if err := c.BindQuery(&req); err != nil {
		errorResp(c, http.StatusBadRequest, xerrors.Errorf("Param error"))
		return
	}
	if len(req.Identity) == 0 {
		errorResp(c, http.StatusBadRequest, xerrors.Errorf("Param missing"))
		return
	}
	req.Identity = strings.Split(req.Identity[0], ",")

	ids, pagination := performProofQuery(req)
	c.JSON(http.StatusOK, ProofQueryResponse{
		Pagination: pagination,
		IDs:        ids,
	})
}

func performProofQuery(req ProofQueryRequest) ([]ProofQueryResponseSingle, ProofQueryPaginationResponse) {
	pagination := ProofQueryPaginationResponse{
		Total:   0,
		Per:     PER_PAGE,
		Current: req.Page,
		Next:    0,
	}
	if pagination.Current <= 0 { // `page` param not provided. Set it to 1.
		pagination.Current = 1
	}
	offsetCount := pagination.Per * (pagination.Current - 1)

	result := make([]ProofQueryResponseSingle, 0, 0)
	proofs := make([]model.Proof, 0, 0)
	tx := model.ReadOnlyDB.Model(&model.Proof{})

	// support selected fields only.
	orderBy := "id"
	order := "desc"
	switch strings.ToLower(req.SortBy) {
	case "id", "last_arweave_id", "created_at", "last_checked_at", "proof_chain_id", "platform", "identity", "alt_id":
		orderBy = strings.ToLower(req.SortBy)
	}
	switch strings.ToLower(req.Order) {
	case "asc", "desc":
		order = strings.ToLower(req.Order)
	}

	if strings.ToLower(req.SortBy) == "activated_at" {
		orderBy = "created_at"
		tx = model.ReadOnlyDB.Table("proof").
			Select("proof.*, proof_chains.*").
			Joins("INNER JOIN proof_chains ON proof.persona = proof_chains.persona").
			Order("proof_chains.created_at " + order).
			Model(&model.Proof{})
	} else {
		tx = tx.Order(orderBy + " " + order)
	}

	switch req.Platform {
	case string(types.Platforms.NextID):
		{
			tx = tx.Where("proof.persona IN ?", req.Identity).Offset(offsetCount).Limit(pagination.Per).Find(&proofs)
			pagination.Total = tx.RowsAffected
		}
	case "":
		{ // All platform
			if req.ExactMatch {
				tx = tx.Where("proof.identity = ? OR proof.alt_id = ?", strings.ToLower(req.Identity[0]), strings.ToLower(req.Identity[0]))
			} else {
				tx = tx.Where("proof.identity LIKE ? OR proof.alt_id LIKE ?", "%"+strings.ToLower(req.Identity[0])+"%", "%"+strings.ToLower(req.Identity[0])+"%")
			}

			for i, id := range req.Identity {
				if i == 0 {
					continue
				}
				if req.ExactMatch {
					tx = tx.Or("proof.identity = ? OR proof.alt_id = ?", strings.ToLower(id), strings.ToLower(id))
				} else {
					tx = tx.Or("proof.identity LIKE ? OR proof.alt_id LIKE ?", "%"+strings.ToLower(id)+"%", "%"+strings.ToLower(id)+"%")
				}
			}
			countTx := tx // Value-copy another query for total amount calculation
			countTx.Count(&pagination.Total)
			tx = tx.Offset(offsetCount).Limit(pagination.Per).Find(&proofs)
		}
	default:
		{
			tx = tx.Where("proof.platform", req.Platform)
			if req.ExactMatch {
				tx = tx.Where("proof.identity = ? OR proof.alt_id = ?", strings.ToLower(req.Identity[0]), strings.ToLower(req.Identity[0]))
			} else {
				tx = tx.Where("proof.identity LIKE ? OR proof.alt_id LIKE ?", "%"+strings.ToLower(req.Identity[0])+"%", "%"+strings.ToLower(req.Identity[0])+"%")
			}

			for i, id := range req.Identity {
				if i == 0 {
					continue
				}

				if req.ExactMatch {
					tx = tx.Or("proof.identity = ? OR proof.alt_id = ?", strings.ToLower(id), strings.ToLower(id))
				} else {
					tx = tx.Or("proof.identity LIKE ? OR proof.alt_id LIKE ?", "%"+strings.ToLower(id)+"%", "%"+strings.ToLower(id)+"%")
				}
			}
			countTx := tx
			countTx.Count(&pagination.Total)
			tx = tx.Offset(offsetCount).Limit(pagination.Per).Find(&proofs)
		}
	}
	if tx.Error != nil || tx.RowsAffected == int64(0) || len(proofs) == 0 {
		return result, pagination
	}
	// Trigger revalidate procedure
	lo.ForEach(proofs, func(proof model.Proof, i int) {
		if proof.IsOutdated() {
			go triggerRevalidate(proof.ID)
		}
	})

	personas := lo.Map(proofs, func(p model.Proof, _index int) string {
		return p.Persona
	})
	personas = lo.Uniq(personas)

	for _, persona := range personas {
		proofs, err := model.FindAllProofByPersona(persona, orderBy+" "+order)
		if err != nil {
			return result, pagination
		}

		// Find last activation time of persona
		activatedAt := "0"
		latest_pc, _ := model.ProofChainFindLatest(persona)
		if latest_pc != nil {
			activatedAt = strconv.FormatInt(latest_pc.CreatedAt.Unix(), 10)
		}

		single := ProofQueryResponseSingle{
			Persona:     persona,
			Avatar:      persona,
			ActivatedAt: activatedAt,
			Proofs: lo.Map(proofs, func(proof model.Proof, _index int) ProofQueryResponseSingleProof {
				return ProofQueryResponseSingleProof{
					Platform:      proof.Platform,
					Identity:      proof.Identity,
					AltID:         proof.AltID,
					CreatedAt:     strconv.FormatInt(proof.CreatedAt.Unix(), 10),
					LastCheckedAt: strconv.FormatInt(proof.LastCheckedAt.Unix(), 10),
					IsValid:       proof.IsValid,
					InvalidReason: proof.InvalidReason,
				}
			}),
		}

		// TODO: optimize performance here?
		lastPc := model.ProofChain{}
		tx = model.ReadOnlyDB.Where("persona = ?", persona).Last(&lastPc)
		if tx.Error != nil {
			return result, pagination
		}

		single.LastArweaveID = lastPc.ArweaveID

		result = append(result, single)
	}

	if pagination.Total > int64(pagination.Per*pagination.Current) {
		pagination.Next = pagination.Current + 1
	}
	return result, pagination
}

func triggerRevalidate(proofID int64) error {
	switch common.CurrentRuntime {
	case common.Runtimes.Standalone:
		// Revalidate it in a block way since this func will
		// be called under goroutine.
		// FIXME: basiclly duplicated to `cmd/lambda_worker.revalidate_single()`
		proof := model.Proof{}
		tx := model.DB.Preload("ProofChain").Preload("ProofChain.Previous").Where("id = ?", proofID).First(&proof)
		if tx.Error != nil {
			return xerrors.Errorf("%w", tx.Error)
		}
		return proof.Revalidate()
	case common.Runtimes.Lambda:
		// Use AWS SQS to send message to workers
		msg := types.QueueMessage{
			Action:  types.QueueActions.Revalidate,
			ProofID: proofID,
		}

		if err := sqs.Send(msg); err != nil {
			return xerrors.Errorf("Failed to send message to queue: %w", err)
		}
	}

	return nil
}
