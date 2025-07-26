package general

import (
	_ "embed"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

//go:embed content_template.tmpl
var ContentTFTemplate string

type ContentCLIParams struct {
	inputFile     string
	inputIsBase64 bool
}

func CreatePasswordArgParser() (*ContentCLIParams, *flag.FlagSet) {
	var contentParams ContentCLIParams

	var passwordCmd = flag.NewFlagSet("password", flag.ContinueOnError)
	passwordCmd.StringVar(&contentParams.inputFile,
		"content-file",
		"",
		"Read the content from specified file")

	passwordCmd.BoolVar(&contentParams.inputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	return &contentParams, passwordCmd
}

func MakeContentGenerator(kwp *model.ContentWrappingParams, args []string) (model.SubCommandExecution, error) {
	contentParams, passCmd := CreatePasswordArgParser()

	if parseErr := passCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	mdl := model.BaseTerraformCodeModel{
		TFBlockName:              "content",
		EncryptedContentMetadata: kwp.GetMetadataForTerraform("content", ""),
		WrappingKeyCoordinate:    kwp.WrappingKeyCoordinate,
	}

	return func(inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		passwordData, readErr := inputReader("Enter content data",
			contentParams.inputFile,
			contentParams.inputIsBase64,
			false)

		if readErr != nil {
			return "", readErr
		}

		secretDataAsStr := string(passwordData)

		if onlyCiphertext {
			return OutputContentEncryptedContent(kwp, secretDataAsStr)

		} else {
			return OutputDatasourceContentTerraformCode(mdl, kwp, secretDataAsStr)
		}
	}, nil
}

func OutputDatasourceContentTerraformCode(mdl model.BaseTerraformCodeModel, kwp *model.ContentWrappingParams, passwordString string) (string, error) {
	s, err := OutputContentEncryptedContent(kwp, passwordString)
	if err != nil {
		return s, err
	}

	mdl.EncryptedContent.SetValue(s)
	return model.Render("password", ContentTFTemplate, &mdl)
}

func OutputContentEncryptedContent(kwp *model.ContentWrappingParams, passwordString string) (string, error) {
	kwp.ObjectType = general.PasswordObjectType
	helper := core.NewVersionedStringConfidentialDataHelper()
	_ = helper.CreateConfidentialStringData(passwordString, kwp.VersionedConfidentialMetadata)

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
