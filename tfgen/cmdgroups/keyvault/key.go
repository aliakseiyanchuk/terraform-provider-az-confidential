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
	"strings"
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
		"destination-vault",
		"",
		"Destination vault name")

	keyCmd.StringVar(&keyParams.vaultObjectName,
		"destination-key-name",
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

	return func(inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		jwkKey, acquireErr := AcquireKey(keyParams, inputReader)
		if acquireErr != nil {
			return "", acquireErr
		}

		mdl.AddDefaultKeyOperationsFor(jwkKey)

		if onlyCiphertext {
			rsaKey, rsaKeyErr := kwp.LoadRsaPublicKey()
			if rsaKeyErr != nil {
				return "", rsaKeyErr
			}

			var coord *core.AzKeyVaultObjectCoordinate
			if kwp.LockPlacement {
				coord = &core.AzKeyVaultObjectCoordinate{
					VaultName: keyParams.vaultName,
					Name:      keyParams.vaultObjectName,
					Type:      "keys",
				}
			}

			em, emErr := keyvault.CreateKeyEncryptedMessage(jwkKey, coord, kwp.SecondaryProtectionParameters, rsaKey)
			if emErr != nil {
				return "", emErr
			}

			fld := model.FoldString(em.ToBase64PEM(), 80)
			return strings.Join(fld, "\n"), nil
		} else {
			mdl.AddDefaultKeyOperationsFor(jwkKey)
			return OutputKeyTerraformCode(mdl, kwp, jwkKey)
		}
	}, nil
}

func PrivateKeyNeedsPassword(keyData []byte) bool {
	if !core.IsPEMEncoded(keyData) {
		// We need password if PKCS8 bag cannot be opened without a password.
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
	keyData, readErr := inputReader("Enter key data (hit Enter twice to end input)",
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
			if pwd, pwdErr := inputReader("Private key requires password", keyParams.passwordFromFile, false, false); pwdErr != nil {
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

func OutputKeyTerraformCode(mdl KeyResourceTerraformModel, kwp *model.ContentWrappingParams, jwkKey interface{}) (string, error) {
	rsaKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return "", rsaKeyErr
	}

	var lockCoord *core.AzKeyVaultObjectCoordinate
	if kwp.LockPlacement {
		lockCoord = &core.AzKeyVaultObjectCoordinate{
			VaultName: mdl.DestinationCoordinate.VaultName.Value,
			Name:      mdl.DestinationCoordinate.ObjectName.Value,
		}
	}

	em, emErr := keyvault.CreateKeyEncryptedMessage(jwkKey, lockCoord, kwp.SecondaryProtectionParameters, rsaKey)
	if emErr != nil {
		return "", emErr
	}

	mdl.EncryptedContent.SetValue(em.ToBase64PEM())
	mdl.EncryptedContentMetadata = kwp.GetMetadataForTerraform("keyvault key", "destination_key")

	return model.Render("key", keyTFTemplate, &mdl)
}
