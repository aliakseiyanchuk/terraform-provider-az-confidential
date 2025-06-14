package tfgen

import (
	_ "embed"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

const passwordCliArg = "password"

//go:embed password_template.tmpl
var passwordTFTemplate string

var passwordCmd = flag.NewFlagSet(passwordCliArg, flag.ContinueOnError)
var passwordParams = SecretTFGenParams{}

func init() {
	passwordCmd.StringVar(&passwordParams.secretFromFile,
		"password-file",
		"",
		"Read secret from specified file")

	passwordCmd.BoolVar(&passwordParams.secretInputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")
}

func GenerateConfidentialPasswordTemplate(kwp KeyWrappingParams, args []string) (string, error) {
	if parseErr := secretCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	passwordData, readErr := ReadInput("Enter password data",
		secretParams.secretFromFile,
		secretParams.secretInputIsBase64,
		false)

	if readErr != nil {
		return "", readErr
	}

	return OutputDatasourcePasswordTerraformCode(kwp, string(passwordData))
}

func OutputDatasourcePasswordTerraformCode(kwp KeyWrappingParams, secretDataAsStr string) (string, error) {
	payloadBytes := core.WrapStringPayload(secretDataAsStr, "password", kwp.GetLabels())

	em, emErr := core.CreateEncryptedMessage(kwp.LoadedRsaPublicKey, payloadBytes)
	if emErr != nil {
		return "", emErr
	}

	rv := BaseTFTemplateParms{
		EncryptedContent:     em.GetSecretExpr(),
		ContentEncryptionKey: em.GetContentEncryptionKeyExpr(),

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,
	}

	return rv.Render("password", passwordTFTemplate)
}
