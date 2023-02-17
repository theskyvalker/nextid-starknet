package starknet

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/theskyvalker/nextid-starknet/types"
	"github.com/theskyvalker/nextid-starknet/validator"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/nextdotid/proof_server/config"

	mycrypto "github.com/nextdotid/proof_server/util/crypto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	persona_sk *ecdsa.PrivateKey
	wallet_sk  *ecdsa.PrivateKey
)

func before_each(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	config.Init("../../config/config.test.json")
}

func generate() Starknet {
	eth := Starknet{
		Base: &validator.Base{
			Platform: types.Platforms.Starknet,
			Previous: "",
			Action:   types.Actions.Create,
			Extra: map[string]string{
				"wallet_signature": "",
			},
			CreatedAt: time.Now(),
			Uuid:      uuid.New(),
		},
	}
	_, persona_sk = mycrypto.GenerateKeypair()
	eth.Pubkey = &persona_sk.PublicKey

	_, wallet_sk = mycrypto.GenerateKeypair()
	eth.Identity = crypto.PubkeyToAddress(wallet_sk.PublicKey).Hex()

	// Generate sig
	eth.Signature, _ = mycrypto.SignPersonal([]byte(eth.GenerateSignPayload()), persona_sk)
	wallet_sig, _ := mycrypto.SignPersonal([]byte(eth.GenerateSignPayload()), wallet_sk)
	eth.Extra = map[string]string{
		"wallet_signature": base64.StdEncoding.EncodeToString(wallet_sig),
	}

	return eth
}

func Test_GeneratePostPayload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)
		eth := generate()
		require.Equal(t, "", eth.GeneratePostPayload()["default"])
	})
}

func Test_GenerateSignPayload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		eth := generate()
		result := eth.GenerateSignPayload()
		require.Contains(t, result, "\"identity\":\""+strings.ToLower(crypto.PubkeyToAddress(wallet_sk.PublicKey).Hex()))
		require.Contains(t, result, "\"persona\":\"0x"+mycrypto.CompressedPubkeyHex(eth.Pubkey))
		require.Contains(t, result, "\"platform\":\"starknet\"")
	})
}

func Test_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		eth := generate()
		require.Nil(t, eth.Validate())
		require.Equal(t, eth.AltID, eth.Identity)
	})
}

func Test_Validate_Delete(t *testing.T) {
	t.Run("signed by persona", func(t *testing.T) {
		before_each(t)

		eth := generate()
		eth.Action = types.Actions.Delete
		eth.Extra = map[string]string{
			"wallet_signature": "",
		}
		eth.Signature, _ = mycrypto.SignPersonal([]byte(eth.GenerateSignPayload()), persona_sk)

		require.Nil(t, eth.Validate())
	})

	t.Run("signed by wallet", func(t *testing.T) {
		before_each(t)

		eth := generate()
		eth.Action = types.Actions.Delete
		wallet_sig, _ := mycrypto.SignPersonal([]byte(eth.GenerateSignPayload()), wallet_sk)
		eth.Extra = map[string]string{
			"wallet_signature": base64.StdEncoding.EncodeToString(wallet_sig),
		}

		require.Nil(t, eth.Validate())
	})

	t.Run("signed by persona, but put in wallet_signature", func(t *testing.T) {
		before_each(t)

		eth := generate()
		eth.Action = types.Actions.Delete

		eth.Signature, _ = mycrypto.SignPersonal([]byte(eth.GenerateSignPayload()), persona_sk)
		eth.Extra = map[string]string{
			"wallet_signature": base64.StdEncoding.EncodeToString(eth.Signature),
		}

		require.NotNil(t, eth.Validate())
	})

	t.Run("signed by wallet, but put in eth.Signature", func(t *testing.T) {
		before_each(t)

		before_each(t)

		eth := generate()
		eth.Action = types.Actions.Delete
		eth.Signature, _ = mycrypto.SignPersonal([]byte(eth.GenerateSignPayload()), wallet_sk)
		eth.Extra = map[string]string{}

		require.NotNil(t, eth.Validate())
	})

	t.Run("Send request to starknet API", func(t *testing.T) {
		var msg = "abc"
		var sig = []string{"1234", "3456"}
		var sigLen = len(sig)
		calldata := struct {
			Signature          []string `json:"signature"`
			ContractAddress    string   `json:"contract_address"`
			EntryPointSelector string   `json:"entry_point_selector"`
			Calldata           []string `json:"calldata"`
		}{
			Signature:          []string{},
			ContractAddress:    "0x03bfde4d21ae3d1b4e9571fa89dc99fa41e5e31a610d194538876f06165710b8",
			EntryPointSelector: "0x213dfe25e2ca309c4d615a09cfc95fdb2fc7dc73fbcad12c450fe93b1f2ff9e",
			Calldata:           []string{msg, fmt.Sprint(sigLen), sig[0], sig[1]},
		}

		jsonData, err := json.Marshal(calldata)
		// Convert the data to JSON
		if err != nil {
			panic(err)
		}
		// Create a buffer containing the JSON data
		reqBody := bytes.NewBuffer(jsonData)
		resp, err := http.Post("https://alpha4.starknet.io/feeder_gateway/call_contract", "application/json", reqBody)
		if err != nil {
			panic(err)
		}
		fmt.Println(resp.Status)
		fmt.Println(resp.Body)
	})
}
