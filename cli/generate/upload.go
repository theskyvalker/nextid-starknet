package generate

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/nextdotid/proof_server/config"
	"github.com/nextdotid/proof_server/controller"
	"github.com/nextdotid/proof_server/types"
)

func UploadToProof(gp GenerateParams, personaPublicKey string, createAt string, uuid string, signature []byte, walletSignature []byte) {
	config.InitCliConfig()

	req := controller.ProofUploadRequest{
		Action:        types.Action(gp.Action),
		Platform:      types.Platform(gp.Platform),
		Identity:      strings.ToLower(gp.Identity),
		PublicKey:     personaPublicKey,
		CreatedAt:     createAt,
		Uuid:          uuid,
		ProofLocation: "",
	}

	if types.Action(gp.Action) == types.Actions.Create && types.Platform(gp.Platform) != types.Platforms.Ethereum {
		input := bufio.NewScanner(os.Stdin)
		fmt.Println("Proof Location (find out how to get the proof location for each platform at README.md):")
		input.Scan()
		req.ProofLocation = input.Text()
	}

	req.Extra.Signature = base64.StdEncoding.EncodeToString((signature))
	if types.Platform(gp.Platform) == types.Platforms.Ethereum {
		req.Extra.EthereumWalletSignature = base64.StdEncoding.EncodeToString((walletSignature))
	}

	url := getUploadUrl()
	client := resty.New()
	resp, err := client.R().SetBody(req).EnableTrace().Post(url)

	if resp.StatusCode() == http.StatusCreated {
		fmt.Println("Upload succeed!!")
	} else {
		panic(fmt.Sprintf("Oops, some error occured. resp:%v err:%v", resp, err))
	}
	os.Exit(0)
}

func getUploadUrl() string {
	return config.Viper.GetString("server.hostname") + config.Viper.GetString("server.upload_path")
}
