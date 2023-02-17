package starknet

import (
	"testing"
	"time"

	"github.com/nextdotid/proof_server/types"
	"github.com/nextdotid/proof_server/validator"

	"github.com/nextdotid/proof_server/config"

	"github.com/google/uuid"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func before_each(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	config.Init("../../config/config.test.json")
}

func generate() Starknet {
	stark := Starknet{
		Base: &validator.Base{
			Platform: types.Platforms.Starknet,
			Previous: "",
			Action:   types.Actions.Create,
			Extra: map[string]string{
				"wallet_signature": "",
			},
			CreatedAt:        time.Now(),
			Uuid:             uuid.New(),
			SignaturePayload: "3520273587237708651253977228499098280589764163116274059542484346740029918998", // hash of the verification message
		},
	}

	// Unlike in Ethereum where a wallet is created with a public and private key pair, StarkNet Accounts are
	//the only way to sign transactions and messages, and verify signatures. Therefore a Account - Contract interface is needed
	stark.Identity = "0x03bFdE4d21ae3D1B4E9571Fa89Dc99FA41E5e31a610D194538876f06165710b8"

	// generated externally using the ArgentX wallet - the validity of a signature is dependent on the contract implementation and not
	// the same as decode with public key as in the case of Ethereum
	wallet_sig := "3382252539845288842311206567753857396558636059826743466845117737485438021889" + "||" + "596802480637334620808800418584779776129374673727264892789729926457993507545"
	stark.Extra = map[string]string{
		"wallet_signature": wallet_sig,
	}

	return stark
}

func Test_GenerateSignPayload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		stark := generate()
		result := stark.GenerateSignPayload()
		require.Contains(t, result, "\"identity\":\"0x03bfde4d21ae3d1b4e9571fa89dc99fa41e5e31a610d194538876f06165710b8\"")
		require.Contains(t, result, "\"platform\":\"starknet\"")
	})
}

func Test_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		stark := generate()

		require.Nil(t, stark.Validate())
		require.Equal(t, stark.AltID, stark.Identity)
	})

	t.Run("valid signature but from a different wallet address", func(t *testing.T) {
		before_each(t)

		before_each(t)

		stark := generate()
		stark.Identity = "0x05dbb2ed1b75db533b7982ab8da8fede379f8d80588bfad9687a0e4caf0726c3"

		require.NotNil(t, stark.Validate())
	})
}

func Test_Validate_Delete(t *testing.T) {

	t.Run("signed by wallet", func(t *testing.T) {
		before_each(t)

		stark := generate()
		stark.Action = types.Actions.Delete
		require.Nil(t, stark.Validate())
	})

	t.Run("invalid signature sent", func(t *testing.T) {
		before_each(t)

		before_each(t)

		stark := generate()
		stark.Action = types.Actions.Delete
		wallet_sig := "2220936504591834982582645768094644581844341042085149784265801550856083971232" + "||" + "1186901391219613604387338410509285983431530640498682227535513990575472109867"
		stark.Extra = map[string]string{
			"wallet_signature": wallet_sig,
		}

		require.NotNil(t, stark.Validate())
	})

}
