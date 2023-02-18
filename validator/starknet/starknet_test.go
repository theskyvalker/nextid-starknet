package starknet

import (
	"strings"
	"testing"

	"github.com/nextdotid/proof_server/types"
	"github.com/nextdotid/proof_server/validator"

	"github.com/nextdotid/proof_server/config"
	"github.com/nextdotid/proof_server/util"

	"github.com/google/uuid"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func before_each(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	config.Init("../../config/config.test.json")
}

const MESSAGE_HASH = "320279730965858634396468303765984608538938284205887195764322493310928683061"
const STARKNET_ADDRESS = "0x03bFdE4d21ae3D1B4E9571Fa89Dc99FA41E5e31a610D194538876f06165710b8"
const WALLET_SIGNATURE = "488187255826154179061086127578568952819680137395366893545703981426270655883" + "||" + "2188625422100965913401240109321955938289053035570120614581710563892295268097"

/*
Verification Message payload used in the test cases

	{
	  "types": {
	    "StarkNetDomain": [
	      {
	        "name": "name",
	        "type": "felt"
	      }
	    ],
	    "Verification": [
	      {
	        "name": "uuid",
	        "type": "string"
	      },
	      {
	        "name": "identity",
	        "type": "felt"
	      },
	      {
	        "name": "platform",
	        "type": "felt"
	      },
	      {
	        "name": "createdAt",
	        "type": "felt"
	      },
	      {
	        "name": "action",
	        "type": "felt"
	      },
	      {
	        "name": "previous",
	        "type": "felt"
	      }
	    ]
	  },
	  "primaryType": "Verification",
	  "domain": {
	    "name": "Verification Message"
	  },
	  "message": {
	    "uuid": "0x97cc2af1e41740f08e195898abfc9848",
	    "identity": "0x03bfde4d21ae3d1b4e9571fa89dc99fa41e5e31a610d194538876f06165710b8",
	    "platform": "starknet",
	    "createdAt": "1676694957",
	    "action": "create",
	    "previous": "null"
	  }
	}
*/
func generate() Starknet {
	createdAt, _ := util.TimestampStringToTime("1676694957")
	stark := Starknet{
		Base: &validator.Base{
			Platform: types.Platforms.Starknet,
			Previous: "",
			Action:   types.Actions.Create,
			Extra: map[string]string{
				"wallet_signature": "",
			},
			CreatedAt: createdAt,
			Uuid:      uuid.MustParse("97cc2af1-e417-40f0-8e19-5898abfc9848"),
		},
	}

	// Unlike in Ethereum where a wallet is created with a public and private key pair, StarkNet Accounts are
	//the only way to sign transactions and messages, and verify signatures. Therefore a Account - Contract interface is needed
	stark.Identity = STARKNET_ADDRESS

	// generated using the ArgentX wallet - the validity of a signature is dependent on the contract implementation
	// as per Starknet account abstraction
	stark.Extra = map[string]string{
		"wallet_signature": WALLET_SIGNATURE,
	}

	return stark
}

func Test_GenerateSignPayload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		stark := generate()
		result := stark.GenerateSignPayload()
		require.Contains(t, result, "\"identity\":\""+strings.ToLower(STARKNET_ADDRESS)+"\"")
		require.Contains(t, result, "\"platform\":\"starknet\"")
	})
}

func Test_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		stark := generate()
		stark.SignaturePayload = MESSAGE_HASH // hash of the verification message
		require.Nil(t, stark.Validate())
		require.Equal(t, stark.AltID, stark.Identity)
	})

	t.Run("valid signature but from a different wallet address", func(t *testing.T) {
		before_each(t)

		before_each(t)

		stark := generate()

		stark.SignaturePayload = MESSAGE_HASH
		stark.Identity = "0x05dbb2ed1b75db533b7982ab8da8fede379f8d80588bfad9687a0e4caf0726c3"

		require.NotNil(t, stark.Validate())
	})
}

func Test_Validate_Delete(t *testing.T) {

	t.Run("signed by wallet", func(t *testing.T) {
		before_each(t)

		stark := generate()
		stark.Action = types.Actions.Delete
		stark.SignaturePayload = MESSAGE_HASH // hash of the verification message
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
