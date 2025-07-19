package general

import (
	_ "embed"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

//go:embed password_template.tmpl
var passwordTFTemplate string

type PasswordCLIParams struct {
	inputFile     string
	inputIsBase64 bool
}

func CreatePasswordArgParser() (*PasswordCLIParams, *flag.FlagSet) {
	var passwordParams PasswordCLIParams

	var passwordCmd = flag.NewFlagSet("password", flag.ContinueOnError)
	passwordCmd.StringVar(&passwordParams.inputFile,
		"password-file",
		"",
		"Read password from specified file")

	passwordCmd.BoolVar(&passwordParams.inputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	return &passwordParams, passwordCmd
}

func MakePasswordGenerator(kwp *model.ContentWrappingParams, args []string) (model.SubCommandExecution, error) {
	passwordParams, passCmd := CreatePasswordArgParser()

	if parseErr := passCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	mdl := model.BaseTerraformCodeModel{
		TFBlockName:           "password",
		CiphertextLabels:      kwp.GetLabels(),
		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
	}

	return func(params model.ContentWrappingParams, inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		passwordData, readErr := inputReader("Enter password data",
			passwordParams.inputFile,
			passwordParams.inputIsBase64,
			false)

		if readErr != nil {
			return "", readErr
		}

		secretDataAsStr := string(passwordData)

		if onlyCiphertext {
			return OutputPasswordEncryptedContent(kwp, secretDataAsStr)

		} else {
			return OutputDatasourcePasswordTerraformCode(mdl, kwp, secretDataAsStr)
		}
	}, nil
}

func OutputDatasourcePasswordTerraformCode(mdl model.BaseTerraformCodeModel, kwp *model.ContentWrappingParams, passwordString string) (string, error) {
	s, err := OutputPasswordEncryptedContent(kwp, passwordString)
	if err != nil {
		return s, err
	}

	mdl.EncryptedContent.SetValue(s)
	return model.Render("password", passwordTFTemplate, &mdl)
}

func OutputPasswordEncryptedContent(kwp *model.ContentWrappingParams, passwordString string) (string, error) {
	helper := core.NewVersionedStringConfidentialDataHelper()
	_ = helper.CreateConfidentialStringData(passwordString, resources.PasswordObjectType, kwp.GetLabels())

	rsaKey, loadErr := kwp.LoadRsaPublicKey()
	if loadErr != nil {
		return "", loadErr
	}

	em, err := helper.ToEncryptedMessage(rsaKey)
	if err != nil {
		return "", err
	}

	return em.ToBase64PEM(), nil
}
