package general

import (
	_ "embed"
	"errors"
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
	if kwp.LockPlacement {
		return nil, errors.New("lock placement constraints are not possible for content; content is unpacked into Terraform state. Use provider limits instead")
	}

	contentParams, passCmd := CreatePasswordArgParser()

	if parseErr := passCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	mdl := model.BaseTerraformCodeModel{
		TFBlockName:           "content",
		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
	}

	return func(inputReader model.InputReader) (model.TerraformCode, core.EncryptedMessage, error) {
		contentBytes, readErr := inputReader(ContentPrompt,
			contentParams.inputFile,
			contentParams.inputIsBase64,
			false)

		if readErr != nil {
			return "", core.EncryptedMessage{}, readErr
		}
		if len(contentBytes) == 0 {
			return "", core.EncryptedMessage{}, errors.New("protecting empty content is superfluous")
		}

		content := string(contentBytes)

		return OutputDatasourceContentTerraformCode(mdl, kwp, content)
	}, nil
}

func OutputDatasourceContentTerraformCode(mdl model.BaseTerraformCodeModel, kwp *model.ContentWrappingParams, content string) (model.TerraformCode, core.EncryptedMessage, error) {
	em, err := makeContentEncryptedMessage(kwp, content)
	if err != nil {
		return "", em, err
	}

	mdl.EncryptedContent.SetValue(model.Ciphertext(em.ToBase64PEM()))
	mdl.EncryptedContentMetadata = kwp.GetMetadataForTerraform("content", "")
	mdl.EncryptedContentMetadata.ResourceHasDestination = false

	tfCode, modelErr := model.Render("content", ContentTFTemplate, &mdl)
	return tfCode, em, modelErr
}

func makeContentEncryptedMessage(kwp *model.ContentWrappingParams, content string) (core.EncryptedMessage, error) {
	rsaKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return core.EncryptedMessage{}, rsaKeyErr
	}

	params := kwp.SecondaryProtectionParameters
	params.CreateLimit = 0
	// Content does not have a limit to create.
	em, emErr := general.CreateContentEncryptedMessage(content, params, rsaKey)
	return em, emErr
}
