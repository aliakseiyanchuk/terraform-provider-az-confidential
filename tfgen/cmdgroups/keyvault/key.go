package keyvault

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

//go:embed key_template.tmpl
var keyTFTemplate string

type KeyTFGenParams struct {
	KeyVaultGroupCLIParams

	passwordFromFile string
	symmetric        bool
}

func CreateKeyArgsParser() (*KeyTFGenParams, *flag.FlagSet) {
	keyParams := &KeyTFGenParams{}

	keyCmd := flag.NewFlagSet("key", flag.ExitOnError)

	keyCmd.StringVar(&keyParams.inputFile,
		"key-file",
		"",
		"Read key from specified file")

	keyCmd.StringVar(&keyParams.passwordFromFile,
		"password-file",
		"",
		"Read key password from file")

	keyCmd.BoolVar(&keyParams.inputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	keyCmd.BoolVar(&keyParams.symmetric,
		"symmetric",
		false,
		"Create symmetric key")

	keyCmd.StringVar(&keyParams.vaultName,
		DestinationVaultCliOption.String(),
		"",
		"Destination vault name")

	keyCmd.StringVar(&keyParams.vaultObjectName,
		DestinationVaultKeyCliOption.String(),
		"",
		"Destination key name")

	return keyParams, keyCmd
}

func MakeKeyGenerator(kwp *model.ContentWrappingParams, args ...string) (model.SubCommandExecution, error) {
	keyParams, keyCmd := CreateKeyArgsParser()

	if parseErr := keyCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	if kwp.LockPlacement && !keyParams.SpecifiesVault() {
		return nil, errors.New("options -destination-vault and -destination-key-name must be supplied where ciphertext must be labelled with its intended destination")
	}

	mdl := KeyResourceTerraformModel{
		TerraformCodeModel: TerraformCodeModel{
			BaseTerraformCodeModel: model.BaseTerraformCodeModel{
				TFBlockName:           "key",
				WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
			},

			TagsModel: model.TagsModel{
				IncludeTags: false,
			},

			DestinationCoordinate: NewObjectCoordinateModel(keyParams.vaultName, keyParams.vaultObjectName),

			NotBeforeExample: model.NotBeforeExample(),
			NotAfterExample:  model.NotAfterExample(),
		},
		KeyOperations: nil,
	}

	return func(inputReader model.InputReader) (model.TerraformCode, core.EncryptedMessage, error) {
		jwkKey, acquireErr := AcquireKey(keyParams, inputReader)
		if acquireErr != nil {
			return "", core.EncryptedMessage{}, acquireErr
		}

		mdl.AddDefaultKeyOperationsFor(jwkKey)

		mdl.AddDefaultKeyOperationsFor(jwkKey)
		return OutputKeyTerraformCode(mdl, kwp, jwkKey)
	}, nil
}

func PrivateKeyNeedsPassword(keyData []byte) bool {
	if !core.IsPEMEncoded(keyData) {
		// We need a password if a PKCS8 bag cannot be opened without a password.
		if _, derLoadErr := x509.ParsePKCS8PrivateKey(keyData); derLoadErr != nil {
			return true
		} else {
			return false
		}
	}
	block, blockErr := core.ParseSinglePEMBlock(keyData)
	if blockErr != nil {
		return true
	}

	return block.Type == "ENCRYPTED PRIVATE KEY"
}

func AcquireKey(keyParams *KeyTFGenParams, inputReader model.InputReader) (interface{}, error) {

	keyData, readErr := inputReader(PrivateKeyPrompt,
		keyParams.inputFile,
		keyParams.inputIsBase64,
		true)

	if readErr != nil {
		return "", readErr
	}

	password := ""

	var jwkKey interface{}
	var jwkImportErr error

	if keyParams.symmetric {
		bits := len(keyData) * 8
		if bits != 128 && bits != 192 && bits != 256 {
			return "", fmt.Errorf("invalid symmetric key length: only 128, 192, and 256 bits are allowed, but %d was supplied", bits)
		}

		if jwkKey, jwkImportErr = jwk.Import(keyData); jwkImportErr != nil {
			return "", fmt.Errorf("cannot import symmetric key bytes: %s", jwkImportErr.Error())
		}
	} else {
		if PrivateKeyNeedsPassword(keyData) {
			if pwd, pwdErr := inputReader(PrivateKeyPasswordPrompt, keyParams.passwordFromFile, false, false); pwdErr != nil {
				return nil, pwdErr
			} else {
				password = string(pwd)
			}
		}

		jwkKey, jwkImportErr = keyvault.AcquireJWT(keyData, password)
	}

	return jwkKey, jwkImportErr
}

type KeyResourceTerraformModel struct {
	TerraformCodeModel

	KeyOperations []azkeys.KeyOperation
}

func (g *KeyResourceTerraformModel) HasKeyOperations() bool {
	return len(g.KeyOperations) > 0
}

func (g *KeyResourceTerraformModel) AddDefaultKeyOperationsFor(jwkKey interface{}) {
	if _, rsaOk := jwkKey.(jwk.RSAPrivateKey); rsaOk {
		g.KeyOperations = []azkeys.KeyOperation{
			azkeys.KeyOperationEncrypt,
			azkeys.KeyOperationDecrypt,
			azkeys.KeyOperationSign,
			azkeys.KeyOperationVerify,
			azkeys.KeyOperationWrapKey,
			azkeys.KeyOperationUnwrapKey,
		}
	} else if _, ecOk := jwkKey.(jwk.ECDSAPrivateKey); ecOk {
		g.KeyOperations = []azkeys.KeyOperation{
			azkeys.KeyOperationSign,
			azkeys.KeyOperationVerify,
		}
	} else if _, symOk := jwkKey.(jwk.SymmetricKey); symOk {
		g.KeyOperations = append(g.KeyOperations,
			azkeys.KeyOperationDecrypt,
			azkeys.KeyOperationEncrypt,
			azkeys.KeyOperationSign,
			azkeys.KeyOperationUnwrapKey,
			azkeys.KeyOperationVerify,
			azkeys.KeyOperationWrapKey,
		)
	}
}

func OutputKeyTerraformCode(mdl KeyResourceTerraformModel, kwp *model.ContentWrappingParams, jwkKey interface{}) (model.TerraformCode, core.EncryptedMessage, error) {
	em, params, err := makeKeyEncryptedMessage(mdl, kwp, jwkKey)
	if err != nil {
		return "", em, err
	}

	mdl.EncryptedContent.SetValue(model.Ciphertext(em.ToBase64PEM()))
	mdl.EncryptedContentMetadata = kwp.GetMetadataForTerraformFor(params, "keyvault key", "destination_key")
	mdl.EncryptedContentMetadata.ResourceHasDestination = true

	tfCode, tfCodeErr := model.Render("key", keyTFTemplate, &mdl)
	return tfCode, em, tfCodeErr
}

func makeKeyEncryptedMessage(mdl KeyResourceTerraformModel, kwp *model.ContentWrappingParams, jwkKey interface{}) (core.EncryptedMessage, core.SecondaryProtectionParameters, error) {
	rsaKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return core.EncryptedMessage{}, kwp.SecondaryProtectionParameters, rsaKeyErr
	}

	var lockCoord *core.AzKeyVaultObjectCoordinate
	if kwp.LockPlacement {
		lockCoord = &core.AzKeyVaultObjectCoordinate{
			VaultName: mdl.DestinationCoordinate.VaultName.Value,
			Name:      mdl.DestinationCoordinate.ObjectName.Value,
			Type:      "keys",
		}
	}

	em, md, emErr := keyvault.CreateKeyEncryptedMessage(jwkKey, lockCoord, kwp.SecondaryProtectionParameters, rsaKey)
	return em, md, emErr
}
