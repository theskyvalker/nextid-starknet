package keybase

import (
	"testing"

	"github.com/google/uuid"
	"github.com/nextdotid/proof_server/config"
	"github.com/nextdotid/proof_server/types"
	"github.com/nextdotid/proof_server/util"
	mycrypto "github.com/nextdotid/proof_server/util/crypto"
	"github.com/nextdotid/proof_server/validator"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func before_each(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	config.Init("../../config/config.test.json")
}

func generate() Keybase {
	pubkey, _ := mycrypto.StringToPubkey("0x02a68c664d4165a7abbb0b4221831153c5f3b0ecb6f994ba95c696eb64ca37eebc")
	created_at, _ := util.TimestampStringToTime("1647329002")

	return Keybase{
		Base: &validator.Base{
			Previous:  "",
			Action:    "create",
			Pubkey:    pubkey,
			Identity:  "nykma",
			Platform:  types.Platforms.Keybase,
			CreatedAt: created_at,
			Uuid:      uuid.MustParse("909ee81f-4c5e-4319-affa-90d95eca614d"),
		},
	}
}

func Test_GeneratePostPayload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		kb := generate()
		result := kb.GeneratePostPayload()
		require.Contains(t, result["default"], "To validate")
		require.Contains(t, result["default"], mycrypto.CompressedPubkeyHex(kb.Pubkey))
		require.Contains(t, result["default"], "%SIG_BASE64%")
	})
}

func Test_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		before_each(t)

		kb := generate()
		kb.Identity = "NYKma"
		require.Nil(t, kb.Validate())
		require.Greater(t, len(kb.Signature), 10)
		require.Equal(t, "nykma", kb.Identity)
		require.Equal(t, kb.Identity, kb.AltID)
	})
}
