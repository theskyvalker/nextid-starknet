package starknet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/dontpanicdao/caigo"
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

type StarkNetVerificationMessage struct {
	uuid      string
	identity  string
	platform  string
	createdAt string
	action    string
	previous  string
}

func (msg StarkNetVerificationMessage) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
	if field == "uuid" {
		fmtEnc = append(fmtEnc, UTF8StrToBig(HexToShortStr(msg.uuid)))
	} else if field == "identity" {
		fmtEnc = append(fmtEnc, UTF8StrToBig(HexToShortStr(msg.identity)))
	} else if field == "platform" {
		fmtEnc = append(fmtEnc, StrToFelt(msg.platform).Big())
	} else if field == "createdAt" {
		fmtEnc = append(fmtEnc, StrToFelt(msg.createdAt).Big())
	} else if field == "action" {
		fmtEnc = append(fmtEnc, StrToFelt(msg.action).Big())
	} else if field == "previous" {
		fmtEnc = append(fmtEnc, StrToFelt(msg.previous).Big())
	}
	return fmtEnc
}

const (
	//64 characters for Starknet addresses instead of 40 for ETH
	VALIDATE_TEMPLATE        = `^{"starknet_address":"0x([0-9a-fA-F]{64})","signature":"(.*)"}$`
	FIELD_PRIME       string = "3618502788666131213697322783095070105623107215331596699973092056135872020481"
)

var (
	l           = logrus.WithFields(logrus.Fields{"module": "validator", "validator": "starknet"})
	re          = regexp.MustCompile(VALIDATE_TEMPLATE)
	MaxFelt     = StrToFelt(FIELD_PRIME)
	asciiRegexp = regexp.MustCompile(`^([[:graph:]]|[[:space:]]){1,31}$`)
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

// convert utf8 string to big int
func UTF8StrToBig(str string) *big.Int {
	hexStr := hex.EncodeToString([]byte(str))
	b, _ := new(big.Int).SetString(hexStr, 16)

	return b
}

// Felt represents Field Element or Felt from cairo.
type Felt struct {
	*big.Int
}

// Big converts a Felt to its big.Int representation.
func (f *Felt) Big() *big.Int {
	return new(big.Int).SetBytes(f.Int.Bytes())
}

func (f *Felt) strToFelt(str string) bool {
	if b, ok := new(big.Int).SetString(str, 0); ok {
		f.Int = b
		return ok
	}

	// TODO: revisit conversation on seperate 'ShortString' conversion
	if asciiRegexp.MatchString(str) {
		hexStr := hex.EncodeToString([]byte(str))
		if b, ok := new(big.Int).SetString(hexStr, 16); ok {
			f.Int = b
			return ok
		}
	}
	return false
}

// StrToFelt converts a string containing a decimal, hexadecimal or UTF8 charset into a Felt.
func StrToFelt(str string) *Felt {
	f := new(Felt)
	if ok := f.strToFelt(str); ok {
		return f
	}
	return nil
}

// trim "0x" prefix(if exists) and converts hexidecimal string to big int
func HexToBN(hexString string) *big.Int {
	numStr := strings.Replace(hexString, "0x", "", -1)

	n, _ := new(big.Int).SetString(numStr, 16)
	return n
}

// convert hex string to StarkNet 'short string'
func HexToShortStr(hexStr string) string {
	numStr := strings.Replace(hexStr, "0x", "", -1)
	hb, _ := new(big.Int).SetString(numStr, 16)

	return string(hb.Bytes())
}

// convert big int to hexidecimal string
func BigToHex(in *big.Int) string {
	return fmt.Sprintf("0x%x", in)
}

// Not used by Starknet.
func (*Starknet) GeneratePostPayload() (post map[string]string) {
	return map[string]string{"default": ""}
}

func (st *Starknet) GenerateSignPayload() (payload string) {
	payloadStruct := validator.H{
		"uuid":       st.Uuid.String(),
		"identity":   strings.ToLower(st.Identity),
		"platform":   "starknet",
		"created_at": util.TimeToTimestampString(st.CreatedAt),
		"action":     string(st.Action),
		"prev":       nil,
	}
	if st.Previous != "" {
		payloadStruct["prev"] = st.Previous
	}
	payloadBytes, err := json.Marshal(payloadStruct)
	if err != nil {
		l.Warnf("Error when marshaling struct: %s", err.Error())
	}

	var ttd = generateStarkNetMessage(payloadStruct)
	var verificationMessage = StarkNetVerificationMessage{
		uuid:      "0x" + strings.ReplaceAll(payloadStruct["uuid"].(string), "-", ""),
		identity:  payloadStruct["identity"].(string),
		platform:  "starknet",
		createdAt: util.TimeToTimestampString(st.CreatedAt),
		action:    string(st.Action),
		previous:  "null",
	}

	hash, hash_err := ttd.GetMessageHash(HexToBN(payloadStruct["identity"].(string)), verificationMessage, caigo.Curve)
	if hash_err != nil {
		panic("Error when computing hash of the payload, verification will fail")
	}
	payload = string(payloadBytes)
	st.Extra["payloadHash"] = hash.String()
	return payload
}

func generateStarkNetMessage(st validator.H) (ttd caigo.TypedData) {

	exampleTypes := make(map[string]caigo.TypeDef)
	domDefs := []caigo.Definition{{"name", "felt"}}
	exampleTypes["StarkNetDomain"] = caigo.TypeDef{Definitions: domDefs}
	verificationDefs := []caigo.Definition{
		{"uuid", "felt"},
		{"identity", "felt"},
		{"platform", "felt"},
		{"createdAt", "felt"},
		{"action", "felt"},
		{"previous", "felt"}}
	exampleTypes["Verification"] = caigo.TypeDef{Definitions: verificationDefs}

	dm := caigo.Domain{
		Name: "Verification Message",
	}

	ttd, _ = caigo.NewTypedData(exampleTypes, "Verification", dm)
	return ttd
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

	if err := validateStarkSignature(wallet_sig, st.Extra["payloadHash"], st.Identity); err != nil {
		return xerrors.Errorf("%w", err)
	}

	return err
}

// `address` should be hexstring, `sig` should be a string of signature parts joined with || to be separated before passing as calldata
// `payload_hash` is the pedersen hash of the payload data used to generate the signature which also includes a prefix to differentiate between
// messages and transactions.
func validateStarkSignature(sig string, payloadHash string, address string) error {
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

	if err := validateStarkSignature(walletSignature, st.Extra["payloadHash"], st.Identity); err != nil {
		return xerrors.Errorf("%w", err)
	}

	return err
}
