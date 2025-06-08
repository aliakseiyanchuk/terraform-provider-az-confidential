package main

import (
	_ "embed"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

const keyCliArg = "key"

//go:embed key_template.tmpl
var keyTFTemplate string

var keyCmd = flag.NewFlagSet(keyCliArg, flag.ContinueOnError)

type KeyTFGetParams struct {
	SecretTFGenParams

	symmetric bool
}

var keyParams = KeyTFGetParams{}

func init() {
	keyCmd.StringVar(&keyParams.secretFromFile,
		"secret-file",
		"",
		"Read secret from specified file")

	keyCmd.BoolVar(&keyParams.secretInputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	keyCmd.BoolVar(&keyParams.symmetric,
		"symmetric",
		false,
		"Create symmetric key")
}

func generateConfidentialKeyTerraformTemplate(kwp KeyWrappingParams, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	if parseErr := keyCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	keyData, readErr := ReadInput("Enter key data (hit Enter twice to end input)",
		secretParams.secretFromFile,
		secretParams.secretInputIsBase64,
		true)

	if readErr != nil {
		return "", readErr
	}

	objType := "key"
	if keyParams.symmetric {
		objType = "symmetric-key"
	}
	payloadBytes := core.WrapBinaryPayload(keyData, objType, kwp.GetLabels())
	fmt.Println(base64.StdEncoding.EncodeToString(payloadBytes))

	em, emErr := core.CreateEncryptedMessage(kwp.loadedRsaPublicKey, payloadBytes)
	if emErr != nil {
		return "", emErr
	}

	rv := BaseTFTemplateParms{
		EncryptedContent:     em.GetSecretExpr(),
		ContentEncryptionKey: em.GetContentEncryptionKeyExpr(),

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,
	}

	return rv.Render("key", keyTFTemplate)
}
