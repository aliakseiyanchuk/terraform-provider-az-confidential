package tfgen

import (
	_ "embed"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

const secretCliArg = "secret"

//go:embed templates/secret_template.tmpl
var secretTFTemplate string

var secretCmd = flag.NewFlagSet(secretCliArg, flag.ContinueOnError)

type SecretTFGenParams struct {
	secretFromFile      string
	loadedSecret        []byte
	secretInputIsBase64 bool
}

var secretParams = SecretTFGenParams{}

func init() {
	secretCmd.StringVar(&secretParams.secretFromFile,
		"secret-file",
		"",
		"Read secret from specified file")

	secretCmd.BoolVar(&secretParams.secretInputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")
}

func GenerateConfidentialSecretTerraformTemplate(kwp ContentWrappingParams, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	if parseErr := secretCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	secretData, readErr := ReadInput("Enter secret data",
		secretParams.secretFromFile,
		secretParams.secretInputIsBase64,
		false)

	if readErr != nil {
		return "", readErr
	}

	secretDataAsStr := string(secretData)

	return OutputSecretTerraformCode(kwp, secretDataAsStr, nil)
}

func OutputSecretTerraformCode(kwp ContentWrappingParams, secretDataAsStr string, tags map[string]string) (string, error) {
	payloadBytes := core.WrapStringPayload(secretDataAsStr, "secret", kwp.GetLabels())

	if _, unwrapErr := core.UnwrapPayload(payloadBytes); unwrapErr != nil {
		return "", fmt.Errorf("internal problem: the secret would not be unwrapped correctly: %s, Please report this problem", unwrapErr.Error())
	}

	em, emErr := core.CreateEncryptedMessage(kwp.LoadedRsaPublicKey, payloadBytes)
	if emErr != nil {
		return "", emErr
	}

	rv := BaseTFTemplateParms{
		EncryptedContent:     em.GetSecretExpr(),
		ContentEncryptionKey: em.GetContentEncryptionKeyExpr(),

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,

		Tags: tags,
	}

	return rv.Render("secret", secretTFTemplate)
}
