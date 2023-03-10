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

const EXPECTED_MESSAGE_HASH = "30660353205475811940805148520873833220837533844184313747578289783623080607"
const STARKNET_ADDRESS = "0x03bFdE4d21ae3D1B4E9571Fa89Dc99FA41E5e31a610D194538876f06165710b8"
const WALLET_SIGNATURE = "1927568133494831781130570052215828917522841217152298943353565656320148910208" + "||" + "3310972320574110511061661032611968926599224256204377412823562425785496745834"
const WALLET_SIGNATURE_DELETE = "637543251093039739629931522312377085792720431642153280644631450115763029287" + "||" + "979740807347149755793574091833267855490464326275756745449051192456887578316"

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
	        "type": "felt"
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
	    "uuid": "0x97cc2af1e41740f08e195898abfc9848", //remove - from the uuid string and prepend 0x to be compatible with the hash encoding
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
		require.Equal(t, stark.Extra["payloadHash"], EXPECTED_MESSAGE_HASH) // checking the validity of the starknet message hash needed for sign verification
		require.Contains(t, result, "\"identity\":\""+strings.ToLower(STARKNET_ADDRESS)+"\"")
		require.Contains(t, result, "\"platform\":\"starknet\"")
	})
}

func Test_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		stark := generate()
		stark.GenerateSignPayload() // calling this is important to compute and store the verification message hash

		require.Nil(t, stark.Validate())
		require.Equal(t, stark.AltID, stark.Identity)
	})

	t.Run("valid signature but from a different wallet address", func(t *testing.T) {
		before_each(t)

		before_each(t)

		stark := generate()

		stark.Identity = "0x05dbb2ed1b75db533b7982ab8da8fede379f8d80588bfad9687a0e4caf0726c3"
		stark.GenerateSignPayload() // calling this is important to compute and store the verification message hash

		require.NotNil(t, stark.Validate())
	})
}

func Test_Validate_Delete(t *testing.T) {

	t.Run("signed by wallet", func(t *testing.T) {
		before_each(t)

		stark := generate()
		stark.Action = types.Actions.Delete
		stark.GenerateSignPayload() // calling this is important to compute and store the verification message hash
		stark.Extra["wallet_signature"] = WALLET_SIGNATURE_DELETE
		require.Nil(t, stark.Validate())
	})

	t.Run("invalid signature sent", func(t *testing.T) {
		before_each(t)

		before_each(t)

		stark := generate()
		stark.Action = types.Actions.Delete
		stark.GenerateSignPayload() // calling this is important to compute and store the verification message hash
		stark.Extra["wallet_signature"] = "2220936504591834982582645768094644581844341042085149784265801550856083971232" + "||" + "1186901391219613604387338410509285983431530640498682227535513990575472109867"

		require.NotNil(t, stark.Validate())
	})

}
