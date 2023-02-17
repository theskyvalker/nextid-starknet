package starknet

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/nextdotid/proof_server/types"
	"github.com/nextdotid/proof_server/util"
	mycrypto "github.com/nextdotid/proof_server/util/crypto"
	"github.com/nextdotid/proof_server/validator"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type Starknet struct {
	*validator.Base
}

const (
	VALIDATE_TEMPLATE = `^{"starknet_address":"0x([0-9a-fA-F]{40})","signature":"(.*)"}$`
)

var (
	l  = logrus.WithFields(logrus.Fields{"module": "validator", "validator": "starknet"})
	re = regexp.MustCompile(VALIDATE_TEMPLATE)
)

func Init() {
	if validator.PlatformFactories == nil {
		validator.PlatformFactories = make(map[types.Platform]func(*validator.Base) validator.IValidator)
	}
	validator.PlatformFactories[types.Platforms.Ethereum] = func(base *validator.Base) validator.IValidator {
		stark := Starknet{base}
		return &stark
	}
}

// Not used by etheruem (for now).
func (*Starknet) GeneratePostPayload() (post map[string]string) {
	return map[string]string{"default": ""}
}

func (st *Starknet) GenerateSignPayload() (payload string) {
	payloadStruct := validator.H{
		"action":     string(st.Action),
		"identity":   strings.ToLower(st.Identity),
		"persona":    "0x" + mycrypto.CompressedPubkeyHex(st.Pubkey),
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

// Both persona-signed and wallelt-signed request are vaild.
func (et *Starknet) Validate() (err error) {
	et.SignaturePayload = et.GenerateSignPayload()
	et.Identity = strings.ToLower(et.Identity)
	et.AltID = et.Identity

	switch et.Action {
	case types.Actions.Create:
		{
			return et.validateCreate()
		}
	case types.Actions.Delete:
		{
			return et.validateDelete()
		}
	default:
		{
			return xerrors.Errorf("unknown action: %s", et.Action)
		}
	}
}

func (et *Starknet) validateCreate() (err error) {
	// ETH wallet signature
	wallet_sig, ok := et.Extra["wallet_signature"]
	if !ok {
		return xerrors.Errorf("wallet_signature not found")
	}
	sig_bytes, err := base64.StdEncoding.DecodeString(wallet_sig)
	if err != nil {
		return xerrors.Errorf("error when decoding sig: %w", err)
	}
	if err := validateEthSignature(sig_bytes, et.GenerateSignPayload(), et.Identity); err != nil {
		return xerrors.Errorf("%w", err)
	}

	// Persona signature
	return mycrypto.ValidatePersonalSignature(et.GenerateSignPayload(), et.Signature, et.Pubkey)
}

// `address` should be hexstring, `sig` should be BASE64-ed string.
func validateEthSignature(sig_bytes []byte, payload, address string) error {
	address_given := common.HexToAddress(address)

	puybkey_recovered, err := mycrypto.RecoverPubkeyFromPersonalSignature(payload, sig_bytes)
	if err != nil {
		return xerrors.Errorf("Error when extracting pubkey: %w", err.Error())
	}

	address_recovered := crypto.PubkeyToAddress(*puybkey_recovered)
	if address_recovered.Hex() != address_given.Hex() {
		return xerrors.Errorf("ETH wallet signature validation failed")
	}
	return nil
}

func (et *Starknet) validateDelete() (err error) {
	walletSignature, ok := et.Extra["wallet_signature"]
	if ok && walletSignature != "" { // Validate wallet-signed signature
		sig, err := base64.StdEncoding.DecodeString(walletSignature)
		if err != nil {
			return xerrors.Errorf("error when decoding wallet sig: %w", err)
		}
		et.Signature = sig // FIXME: is this needed to let the whole chain work?

		wallet_pubkey, err := mycrypto.RecoverPubkeyFromPersonalSignature(et.GenerateSignPayload(), sig)
		if err != nil {
			return xerrors.Errorf("error when recovering pubkey from sig: %w", err)
		}
		wallet_address := crypto.PubkeyToAddress(*wallet_pubkey)
		if common.HexToAddress(et.Identity) != wallet_address {
			return xerrors.Errorf("not signed by this wallet: found %s instead of %s", wallet_address.Hex(), et.Identity)
		}

		return nil
	}

	// Vaildate persona-signed siganture
	return mycrypto.ValidatePersonalSignature(et.GenerateSignPayload(), et.Signature, et.Pubkey)
}
