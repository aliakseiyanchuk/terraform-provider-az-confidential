// Copyright (c) HashiCorp, Inc.

package tfgen

import (
	_ "embed"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

const passwordCliArg = "password"

//go:embed templates/password_template.tmpl
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

func GenerateConfidentialPasswordTemplate(kwp ContentWrappingParams, outputTFCode bool, args []string) (string, error) {
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

	if outputTFCode {
		return OutputDatasourcePasswordTerraformCode(kwp, string(passwordData))
	} else {
		return OutputPasswordEncryptedContent(kwp, string(passwordData))
	}
}

func OutputDatasourcePasswordTerraformCode(kwp ContentWrappingParams, passwordString string) (string, error) {
	ciphertext, err := OutputPasswordEncryptedContent(kwp, passwordString)
	if err != nil {
		return ciphertext, err
	}

	rv := BaseTFTemplateParms{
		EncryptedContent: ciphertext,

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,
	}

	return rv.Render("password", passwordTFTemplate)
}

func OutputPasswordEncryptedContent(kwp ContentWrappingParams, passwordString string) (string, error) {
	return OutputEncryptedConfidentialData(kwp, core.CreateConfidentialStringData(passwordString, "password", kwp.GetLabels()))
}
