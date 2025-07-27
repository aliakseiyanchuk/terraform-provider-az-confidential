package keyvault

import (
	_ "embed"
	"errors"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"strings"
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
	if kwp.LockPlacement && !secretParams.SpecifiesVault() {
		return nil, errors.New("options -destination-vault and -destination-secret-name must be supplied where ciphertext must be labelled with its intended destination")
	}

	mdl := TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "secret",
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		TagsModel: model.TagsModel{
			IncludeTags: true,
		},

		NotBeforeExample: model.NotBeforeExample(),
		NotAfterExample:  model.NotAfterExample(),

		DestinationCoordinate: NewObjectCoordinateModel(secretParams.vaultName, secretParams.vaultObjectName),
	}

	return func(inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		secretData, readErr := inputReader("Enter secret data",
			secretParams.inputFile,
			secretParams.inputIsBase64,
			false)

		if readErr != nil {
			return "", readErr
		}
		secretDataAsStr := string(secretData)

		if onlyCiphertext {
			em, _, err := makeSecretEncryptedMessage(mdl, kwp, secretDataAsStr)
			if err != nil {
				return "", err
			}

			fld := model.FoldString(em.ToBase64PEM(), 80)
			return strings.Join(fld, "\n"), nil
		}

		return OutputSecretTerraformCode(mdl, kwp, secretDataAsStr)

	}, nil
}

func OutputSecretTerraformCode(mdl TerraformCodeModel, kwp *model.ContentWrappingParams, secretDataAsStr string) (string, error) {
	em, params, err := makeSecretEncryptedMessage(mdl, kwp, secretDataAsStr)
	if err != nil {
		return "", err
	}

	mdl.BaseTerraformCodeModel.EncryptedContentMetadata = kwp.GetMetadataForTerraformFor(params, "keyvault secret", "destination_secret")
	mdl.EncryptedContent.SetValue(em.ToBase64PEM())
	mdl.EncryptedContentMetadata.ResourceHasDestination = true

	return model.Render("secret", secretTFTemplate, &mdl)
}

func makeSecretEncryptedMessage(mdl TerraformCodeModel, kwp *model.ContentWrappingParams, secretDataAsStr string) (core.EncryptedMessage, core.SecondaryProtectionParameters, error) {
	rsaKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return core.EncryptedMessage{}, kwp.SecondaryProtectionParameters, rsaKeyErr
	}

	var lockCoord *core.AzKeyVaultObjectCoordinate
	if kwp.LockPlacement {
		lockCoord = &core.AzKeyVaultObjectCoordinate{
			VaultName: mdl.DestinationCoordinate.VaultName.Value,
			Name:      mdl.DestinationCoordinate.ObjectName.Value,
		}
	}

	em, md, emErr := keyvault.CreateSecretEncryptedMessage(secretDataAsStr, lockCoord, kwp.SecondaryProtectionParameters, rsaKey)
	return em, md, emErr
}
