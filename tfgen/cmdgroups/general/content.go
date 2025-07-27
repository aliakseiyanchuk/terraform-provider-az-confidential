package general

import (
	_ "embed"
	"errors"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"strings"
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
		TFBlockName:           "content",
		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
	}

	return func(inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		contentBytes, readErr := inputReader("Enter content data",
			contentParams.inputFile,
			contentParams.inputIsBase64,
			false)

		if readErr != nil {
			return "", readErr
		}
		if len(contentBytes) == 0 {
			return "", errors.New("protecting empty content is superfluous")
		}

		content := string(contentBytes)

		if onlyCiphertext {
			em, err := makeContentEncryptedMessage(kwp, content)
			if err != nil {
				return "", err
			}

			fld := model.FoldString(em.ToBase64PEM(), 80)
			return strings.Join(fld, "\n"), nil

		} else {
			return OutputDatasourceContentTerraformCode(mdl, kwp, content)
		}
	}, nil
}

func OutputDatasourceContentTerraformCode(mdl model.BaseTerraformCodeModel, kwp *model.ContentWrappingParams, content string) (string, error) {
	em, err := makeContentEncryptedMessage(kwp, content)
	if err != nil {
		return "", err
	}

	mdl.EncryptedContent.SetValue(em.ToBase64PEM())
	mdl.EncryptedContentMetadata = kwp.GetMetadataForTerraform("content", "")
	mdl.EncryptedContentMetadata.ResourceHasDestination = false
	return model.Render("content", ContentTFTemplate, &mdl)
}

func makeContentEncryptedMessage(kwp *model.ContentWrappingParams, content string) (core.EncryptedMessage, error) {
	rsaKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return core.EncryptedMessage{}, rsaKeyErr
	}

	em, emErr := general.CreateContentEncryptedMessage(content, kwp.SecondaryProtectionParameters, rsaKey)
	return em, emErr
}
