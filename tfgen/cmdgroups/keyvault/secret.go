package keyvault

import (
	_ "embed"
	"errors"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

//go:embed secret_template.tmpl
var secretTFTemplate string

func CreateSecretArgParser() (*KeyVaultGroupCLIParams, *flag.FlagSet) {
	var secretParams = KeyVaultGroupCLIParams{}

	var secretCmd = flag.NewFlagSet("secret", flag.ExitOnError)

	secretCmd.StringVar(&secretParams.inputFile,
		"secret-file",
		"",
		"Read secret from specified file")

	secretCmd.StringVar(&secretParams.vaultName,
		"destination-vault",
		"",
		"Destination vault name")

	secretCmd.StringVar(&secretParams.vaultObjectName,
		"destination-secret-name",
		"",
		"Destination secret name")

	secretCmd.BoolVar(&secretParams.inputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	return &secretParams, secretCmd
}

func MakeSecretGenerator(kwp *model.ContentWrappingParams, args []string) (model.SubCommandExecution, error) {
	secretParams, secretCmd := CreateSecretArgParser()

	if parseErr := secretCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	if kwp.AddTargetLabel {
		if !secretParams.SpecifiesVault() {
			return nil, errors.New("options -destination-vault and -destination-secret-name must be supplied where ciphertext must be labelled with its intended destination")
		} else {
			coord := core.AzKeyVaultObjectCoordinate{
				VaultName: secretParams.vaultName,
				Name:      secretParams.vaultObjectName,
				Type:      "secrets",
			}

			kwp.AddLabel(coord.GetLabel())
		}
	}

	mdl := TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "secret",
			CiphertextLabels:      kwp.GetLabels(),
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
			//EncryptedContent:      model.NewStringTerraformFieldExpression(),
		},

		TagsModel: model.TagsModel{
			IncludeTags: true,
		},

		NotBeforeExample: model.NotBeforeExample(),
		NotAfterExample:  model.NotAfterExample(),

		DestinationCoordinate: NewObjectCoordinateModel(secretParams.vaultName, secretParams.vaultObjectName),
	}

	return func(params model.ContentWrappingParams, inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		secretData, readErr := inputReader("Enter secret data",
			secretParams.inputFile,
			secretParams.inputIsBase64,
			false)

		if readErr != nil {
			return "", readErr
		}

		secretDataAsStr := string(secretData)

		if onlyCiphertext {
			return OutputSecretEncryptedContent(kwp, secretDataAsStr)

		} else {
			return OutputSecretTerraformCode(mdl, kwp, secretDataAsStr)
		}
	}, nil
}

func OutputSecretTerraformCode(mdl TerraformCodeModel, kwp *model.ContentWrappingParams, secretDataAsStr string) (string, error) {
	s, err := OutputSecretEncryptedContent(kwp, secretDataAsStr)
	if err != nil {
		return s, err
	}

	mdl.EncryptedContent.SetValue(s)
	return model.Render("secret", secretTFTemplate, &mdl)
}

func OutputSecretEncryptedContent(kwp *model.ContentWrappingParams, secretText string) (string, error) {
	helper := core.NewVersionedStringConfidentialDataHelper()
	_ = helper.CreateConfidentialStringData(secretText, keyvault.SecretObjectType, kwp.GetLabels())

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
