package starknet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/nextdotid/proof_server/config"
	"github.com/nextdotid/proof_server/types"
	"github.com/nextdotid/proof_server/util"
	"github.com/nextdotid/proof_server/validator"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type Starknet struct {
	*validator.Base
}

const (
	//64 characters for Starknet addresses instead of 40 for ETH
	VALIDATE_TEMPLATE = `^{"starknet_address":"0x([0-9a-fA-F]{64})","signature":"(.*)"}$`
)

var (
	l  = logrus.WithFields(logrus.Fields{"module": "validator", "validator": "starknet"})
	re = regexp.MustCompile(VALIDATE_TEMPLATE)
)

func Init() {
	if validator.PlatformFactories == nil {
		validator.PlatformFactories = make(map[types.Platform]func(*validator.Base) validator.IValidator)
	}
	validator.PlatformFactories[types.Platforms.Starknet] = func(base *validator.Base) validator.IValidator {
		stark := Starknet{base}
		return &stark
	}
}

// Not used by Starknet.
func (*Starknet) GeneratePostPayload() (post map[string]string) {
	return map[string]string{"default": ""}
}

func (st *Starknet) GenerateSignPayload() (payload string) {
	payloadStruct := validator.H{
		"action":     string(st.Action),
		"identity":   strings.ToLower(st.Identity),
		"platform":   "starknet",
		"prev":       nil,
		"created_at": util.TimeToTimestampString(st.CreatedAt),
		"uuid":       st.Uuid.String(),
	}
	if st.Previous != "" {
		payloadStruct["prev"] = st.Previous
	}
	payloadBytes, err := json.Marshal(payloadStruct)
	if err != nil {
		l.Warnf("Error when marshaling struct: %s", err.Error())
		return ""
	}
	return string(payloadBytes)
}

func generateMessageHash(inpMessage string) string {
	return inpMessage
}

// Only wallet-signed request are vaild.
func (st *Starknet) Validate() (err error) {
	st.Identity = strings.ToLower(st.Identity)
	st.AltID = st.Identity

	switch st.Action {
	case types.Actions.Create:
		{
			return st.validateCreate()
		}
	case types.Actions.Delete:
		{
			return st.validateDelete()
		}
	default:
		{
			return xerrors.Errorf("unknown action: %s", st.Action)
		}
	}
}

func (st *Starknet) validateCreate() (err error) {
	// Starknet wallet signature
	wallet_sig, ok := st.Extra["wallet_signature"]
	if !ok {
		return xerrors.Errorf("wallet_signature not found")
	}
	st.SignaturePayload = generateMessageHash(st.SignaturePayload)

	if err := validateStarkSignature(wallet_sig, st.SignaturePayload, st.Identity); err != nil {
		return xerrors.Errorf("%w", err)
	}

	return err
}

// `address` should be hexstring, `sig` should be a string of signature parts joined with || to be separated before passing as calldata
// `payload_hash` is the pedersen hash of the payload data used to generate the signature which also includes a prefix to differentiate between
// messages and transactions.
func validateStarkSignature(sig string, payloadHash, address string) error {
	address_given := address

	var sigParts = strings.Split(sig, "||")
	var sigLen = len(sigParts)

	calldata := struct {
		Signature          []string `json:"signature"`
		ContractAddress    string   `json:"contract_address"`
		EntryPointSelector string   `json:"entry_point_selector"`
		Calldata           []string `json:"calldata"`
	}{
		Signature:          []string{},
		ContractAddress:    address_given,                                // contract address is the same as the account address
		EntryPointSelector: config.C.Platform.Starknet.ValidSignEndpoint, // this is the same for the is_valid_signature method for diff addresses
		Calldata:           []string{payloadHash, fmt.Sprint(sigLen), sigParts[0], sigParts[1]},
	}

	jsonData, err := json.Marshal(calldata)
	// Convert the data to JSON
	if err != nil {
		return xerrors.Errorf("Found invalid data in signature verification payload.")
	}
	// Create a buffer containing the JSON data
	reqBody := bytes.NewBuffer(jsonData)
	resp, err := http.Post(config.C.Platform.Starknet.ContractCallURL, "application/json", reqBody)
	if err != nil {
		return xerrors.Errorf("Starknet wallet signature verification process failed. Retry.")
	}

	if resp.StatusCode != 200 {
		return xerrors.Errorf("Starknet wallet signature validation failed with error code %d", resp.StatusCode)
	}

	return nil
}

func (st *Starknet) validateDelete() (err error) {
	walletSignature, ok := st.Extra["wallet_signature"]
	if !ok {
		return xerrors.Errorf("wallet signature not found")
	}

	if err := validateStarkSignature(walletSignature, st.SignaturePayload, st.Identity); err != nil {
		return xerrors.Errorf("%w", err)
	}

	return err
}
