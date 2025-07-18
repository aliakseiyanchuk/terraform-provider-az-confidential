package tfgen

import (
	_ "embed"
	"flag"
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

func GenerateConfidentialSecretTerraformTemplate(kwp ContentWrappingParams, inputReader InputReader, produceTFCode bool, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	if parseErr := secretCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	secretData, readErr := inputReader("Enter secret data",
		secretParams.secretFromFile,
		secretParams.secretInputIsBase64,
		false)

	if readErr != nil {
		return "", readErr
	}

	secretDataAsStr := string(secretData)

	kwp.TFBlockNameIfUndefined("secret")
	if produceTFCode {
		return OutputSecretTerraformCode(kwp, secretDataAsStr, true, nil)
	} else {
		return OutputSecretEncryptedContent(kwp, secretDataAsStr)
	}
}

func OutputSecretTerraformCode(kwp ContentWrappingParams, secretDataAsStr string, includeTags bool, tags map[string]string) (string, error) {
	s, err := OutputSecretEncryptedContent(kwp, secretDataAsStr)
	if err != nil {
		return s, err
	}

	rv := BaseTFTemplateParms{
		EncryptedContent: s,
		Labels:           kwp.GetLabels(),

		TFBlockName: kwp.TFBlockName,

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,

		IncludeTags: includeTags,
		Tags:        tags,
	}

	return rv.Render("secret", secretTFTemplate)
}

func OutputSecretEncryptedContent(kwp ContentWrappingParams, secretText string) (string, error) {
	helper := core.NewVersionedStringConfidentialDataHelper()
	_ = helper.CreateConfidentialStringData(secretText, "secret", kwp.GetLabels())
	em, err := helper.ToEncryptedMessage(kwp.LoadedRsaPublicKey)
	if err != nil {
		return "", err
	}

	return em.ToBase64PEM(), nil
}
