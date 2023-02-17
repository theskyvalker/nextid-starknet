package controller

import (
	"crypto/ecdsa"
	"strconv"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/nextdotid/proof_server/model"
	"github.com/nextdotid/proof_server/types"
	"github.com/nextdotid/proof_server/util/crypto"
	"github.com/nextdotid/proof_server/validator"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

const (
	persona string = "0x028c3cda474361179d653c41a62f6bbb07265d535121e19aedf660da2924d0b1e3"
)

func insert_proof(t *testing.T) {
	pubkey, _ := crypto.StringToPubkey(persona)
	validators := []validator.Base{
		{
			Platform:      types.Platforms.Twitter,
			Previous:      "",
			Action:        types.Actions.Create,
			Pubkey:        pubkey,
			Identity:      "yeiwb",
			ProofLocation: "1469221200140574721",
			CreatedAt:     time.Date(1970, time.Month(1), 1, 0, 0, 0, 0, time.UTC),
			Signature:     []byte{1},
		},
		{
			Platform:      types.Platforms.Ethereum,
			Previous:      "AQ==",
			Action:        types.Actions.Create,
			Pubkey:        pubkey,
			Identity:      "0xd5f630652d4a8a5f95cda3738ce9f43fa26e764f",
			ProofLocation: "",
			Signature:     []byte{2},
			Extra: map[string]string{
				"ethereum_pubkey": "0x04ae5933a45605e7fff23cd010455911c1f0194479438859af5140d749937e53fd935d768efa9229ae8be3314631e945c56f915778ad4565b4efafcd13864e2fd7",
			},
		},
	}

	for _, b := range validators {
		pc, err := model.ProofChainCreateFromValidator(&b)
		require.Nil(t, err)

		err = pc.Apply()
		require.Nil(t, err)
	}
}

func insert_proof_exact(t *testing.T) {
	pubkey, _ := crypto.StringToPubkey(persona)
	personaPk, _ := crypto.GenerateKeypair()
	validators := []validator.Base{
		{
			Platform:      types.Platforms.Twitter,
			Previous:      "",
			Action:        types.Actions.Create,
			Pubkey:        pubkey,
			Identity:      "yeiwb",
			ProofLocation: "1469221200140574721",
			Signature:     []byte{1},
			CreatedAt:     time.Date(1970, time.Month(1), 1, 0, 0, 0, 0, time.UTC),
		},
		{
			Platform:      types.Platforms.Ethereum,
			Previous:      "AQ==",
			Action:        types.Actions.Create,
			Pubkey:        pubkey,
			Identity:      "0xd5f630652d4a8a5f95cda3738ce9f43fa26e764f",
			ProofLocation: "",
			Signature:     []byte{2},
			Extra: map[string]string{
				"ethereum_pubkey": "0x04ae5933a45605e7fff23cd010455911c1f0194479438859af5140d749937e53fd935d768efa9229ae8be3314631e945c56f915778ad4565b4efafcd13864e2fd7",
			},
			CreatedAt: time.Date(1971, time.Month(1), 1, 0, 0, 0, 0, time.UTC),
		},
		{
			Platform:      types.Platforms.Twitter,
			Previous:      "",
			Action:        types.Actions.Create,
			Pubkey:        personaPk,
			Identity:      "yeiwb_fuzzy",
			ProofLocation: "1469221200140574722",
			Signature:     []byte{3},
			CreatedAt:     time.Date(2022, time.Month(1), 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, b := range validators {
		pc, err := model.ProofChainCreateFromValidator(&b)
		require.Nil(t, err)

		err = pc.Apply()
		require.Nil(t, err)
	}
}

// / Insert Random Persona <-> Given ETH public key binding.
func insert_eth_proof(t *testing.T, eth_pub_key *ecdsa.PublicKey) {
	personaPk, _ := crypto.GenerateKeypair()
	validator := validator.Base{
		Platform:         types.Platforms.Ethereum,
		Previous:         "",
		Action:           types.Actions.Create,
		Pubkey:           personaPk,
		Identity:         strings.ToLower(ethcrypto.PubkeyToAddress(*eth_pub_key).String()),
		ProofLocation:    "",
		Signature:        []byte{1},
		SignaturePayload: "",
		Text:             "",
		Extra:            map[string]string{},
	}
	pc, err := model.ProofChainCreateFromValidator(&validator)
	require.Nil(t, err)
	err = pc.Apply()
	require.Nil(t, err)
}

func Test_proofQuery(t *testing.T) {
	t.Run("smoke", func(t *testing.T) {
		before_each(t)
		resp := ProofQueryResponse{}

		APITestCall(Engine, "GET", "/v1/proof?platform=twitter&identity=yeiwb", "", &resp)
		require.Equal(t, 0, len(resp.IDs))
	})

	t.Run("success", func(t *testing.T) {
		before_each(t)
		insert_proof(t)

		resp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?platform=twitter&identity=yeiwb", "", &resp)
		require.Equal(t, 1, len(resp.IDs))
		found := resp.IDs[0]
		require.Equal(t, persona, found.Persona)
		require.Equal(t, persona, found.Avatar)
		require.Equal(t, 2, len(found.Proofs))
		require.Equal(t, 0, resp.Pagination.Next)
		require.Equal(t, int64(1), resp.Pagination.Total)
		require.Equal(t, 1, resp.Pagination.Current)
		require.Equal(t, PER_PAGE, resp.Pagination.Per)
		require.NotEqual(t, "0", found.ActivatedAt)
		require.NotEqual(t, "", found.ActivatedAt)

		partial_resp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?platform=twitter&identity=eiw", "", &partial_resp)
		require.Equal(t, 1, len(resp.IDs))
		found = partial_resp.IDs[0]
		require.Equal(t, persona, found.Persona)
		require.Equal(t, persona, found.Avatar)
		require.Equal(t, 2, len(found.Proofs))

		empty_resp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?platform=keybase&identity=yeiwb", "", &empty_resp)
		require.Equal(t, 0, len(empty_resp.IDs))
	})

	t.Run("all platform result", func(t *testing.T) {
		before_each(t)
		insert_proof(t)

		resp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?identity=eiwb", "", &resp)
		require.Equal(t, 1, len(resp.IDs))
		found := resp.IDs[0]
		require.Equal(t, persona, found.Persona)
		require.Equal(t, persona, found.Avatar)
		require.Equal(t, 2, len(found.Proofs))
	})

	t.Run("multiple identity + fuzzy", func(t *testing.T) {
		before_each(t)
		insert_proof(t)

		resp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?identity=eiw,0xd5f630652d4", "", &resp)
		require.Equal(t, 1, len(resp.IDs))
		require.Equal(t, 2, len(resp.IDs[0].Proofs))
	})

	t.Run("persona", func(t *testing.T) {
		before_each(t)
		insert_proof(t)

		resp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?identity="+persona+"&platform=nextid", "", &resp)
		require.Equal(t, 1, len(resp.IDs))
		require.Equal(t, 2, len(resp.IDs[0].Proofs))
	})

	t.Run("pagination", func(t *testing.T) {
		before_each(t)
		eth_pubkey, _ := crypto.GenerateKeypair()
		lo.Times(45, func(i int) int {
			insert_eth_proof(t, eth_pubkey)
			return 0
		})
		eth_address := ethcrypto.PubkeyToAddress(*eth_pubkey).String()
		url := "/v1/proof?identity=" + eth_address + "&platform=ethereum"

		resp_page1 := ProofQueryResponse{} // Page not given
		APITestCall(Engine, "GET", url, nil, &resp_page1)
		require.Equal(t, int64(45), resp_page1.Pagination.Total)
		require.Equal(t, 1, resp_page1.Pagination.Current)
		require.Equal(t, 2, resp_page1.Pagination.Next)
		require.Equal(t, PER_PAGE, len(resp_page1.IDs))

		resp_page3 := ProofQueryResponse{} // Last page
		APITestCall(Engine, "GET", url+"&page=3", nil, &resp_page3)
		require.Equal(t, 3, resp_page3.Pagination.Current)
		require.Equal(t, 0, resp_page3.Pagination.Next)
		require.Equal(t, 5, len(resp_page3.IDs))

		resp_page4 := ProofQueryResponse{} // Page overflow
		APITestCall(Engine, "GET", url+"&page=4", nil, &resp_page4)
		require.Equal(t, 4, resp_page4.Pagination.Current)
		require.Equal(t, 0, resp_page4.Pagination.Next)
		require.Equal(t, 0, len(resp_page4.IDs))
	})

	t.Run("exact_match", func(t *testing.T) {
		before_each(t)
		insert_proof_exact(t)

		resp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?platform=twitter&identity=yeiwb", "", &resp)
		require.Equal(t, 2, len(resp.IDs))

		APITestCall(Engine, "GET", "/v1/proof?platform=twitter&identity=yeiwb&exact=true", "", &resp)
		require.Equal(t, 1, len(resp.IDs))
	})

	t.Run("sort", func(t *testing.T) {
		before_each(t)
		insert_proof(t)

		ascResp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?sort=platform&order=asc&identity="+persona+"&platform=nextid", "", &ascResp)
		require.Equal(t, types.Platform("ethereum"), ascResp.IDs[0].Proofs[0].Platform)

		descResp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?sort=platform&order=desc&identity="+persona+"&platform=nextid", "", &descResp)
		require.Equal(t, types.Platform("twitter"), descResp.IDs[0].Proofs[0].Platform)
	})

	t.Run("sort_activated_at", func(t *testing.T) {
		before_each(t)
		insert_proof_exact(t)

		ascResp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?sort=activated_at&order=asc&identity=yeiwb&platform=twitter", "", &ascResp)
		first, _ := strconv.ParseInt(ascResp.IDs[0].ActivatedAt, 10, 64)
		second, _ := strconv.ParseInt(ascResp.IDs[1].ActivatedAt, 10, 64)
		require.Less(t, first, second)

		descResp := ProofQueryResponse{}
		APITestCall(Engine, "GET", "/v1/proof?sort=activated_at&order=desc&identity=yeiwb&platform=twitter", "", &descResp)
		first, _ = strconv.ParseInt(descResp.IDs[0].ActivatedAt, 10, 64)
		second, _ = strconv.ParseInt(descResp.IDs[1].ActivatedAt, 10, 64)
		require.Greater(t, first, second)
	})
}
