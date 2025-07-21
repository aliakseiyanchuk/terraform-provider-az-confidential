package keyvault

import (
	"crypto/x509"
	_ "embed"
	"encoding/json"
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

	if kwp.LockPlacement {
		if !keyParams.SpecifiesVault() {
			return nil, errors.New("options -destination-vault and -destination-key-name must be supplied where ciphertext must be labelled with its intended destination")
		} else {
			coord := core.AzKeyVaultObjectCoordinate{
				VaultName: keyParams.vaultName,
				Name:      keyParams.vaultObjectName,
				Type:      "keys",
			}

			kwp.AddPlacementConstraints(coord.GetPlacementConstraint())
		}
	}

	mdl := KeyResourceTerraformModel{
		TerraformCodeModel: TerraformCodeModel{
			BaseTerraformCodeModel: model.BaseTerraformCodeModel{
				TFBlockName:              "key",
				EncryptedContentMetadata: kwp.VersionedConfidentialMetadata,
				WrappingKeyCoordinate:    kwp.WrappingKeyCoordinate,
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

		if _, rsaOk := jwkKey.(jwk.RSAPrivateKey); rsaOk {
			mdl.KeyOperations = append(mdl.KeyOperations,
				azkeys.KeyOperationDecrypt,
				azkeys.KeyOperationEncrypt,
				azkeys.KeyOperationSign,
				azkeys.KeyOperationUnwrapKey,
				azkeys.KeyOperationVerify,
				azkeys.KeyOperationWrapKey,
			)
		} else if _, symOk := jwkKey.(jwk.SymmetricKey); symOk {
			mdl.KeyOperations = append(mdl.KeyOperations,
				azkeys.KeyOperationDecrypt,
				azkeys.KeyOperationEncrypt,
				azkeys.KeyOperationSign,
				azkeys.KeyOperationUnwrapKey,
				azkeys.KeyOperationVerify,
				azkeys.KeyOperationWrapKey,
			)
		} else if _, ecOk := jwkKey.(jwk.ECDSAPrivateKey); ecOk {
			mdl.KeyOperations = append(mdl.KeyOperations,
				azkeys.KeyOperationSign,
				azkeys.KeyOperationVerify,
			)
		}

		if onlyCiphertext {
			return OutputKeyEncryptedContent(kwp, jwkKey)
		} else {
			mdl.AddDefaultKeyOperationsFor(jwkKey)
			return OutputKeyTerraformCode(mdl, kwp, jwkKey)
		}
	}, nil
}

func AcquireKey(keyParams *KeyTFGenParams, inputReader model.InputReader) (interface{}, error) {
	keyData, readErr := inputReader("Enter key data (hit Enter twice to end input)",
		keyParams.inputFile,
		keyParams.inputIsBase64,
		true)

	if readErr != nil {
		return "", readErr
	}

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
		if core.IsPEMEncoded(keyData) {
			if block, blockErr := core.ParseSinglePEMBlock(keyData); blockErr != nil {
				return nil, fmt.Errorf("not a valid input: %s", blockErr.Error())
			} else {
				if block.Type == "ENCRYPTED PRIVATE KEY" {
					password, passReadErr := inputReader("Private key requires password", keyParams.passwordFromFile, false, false)
					if passReadErr != nil {
						return nil, passReadErr
					}

					// Try to decrypt the PEM key
					key, loadErr := core.PrivateKeyFromEncryptedBlock(block, string(password))
					if loadErr != nil {
						return nil, fmt.Errorf("unable to load password-protected private key: %s", loadErr.Error())
					}

					if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
						return nil, fmt.Errorf("cannot import rsa key bytes: %s", jwkImportErr.Error())
					}
				} else if block.Type == "PRIVATE KEY" {
					key, loadErr := core.PrivateKeyFromBlock(block)
					if loadErr != nil {
						return nil, fmt.Errorf("cannot import rsa key bytes: %s", loadErr.Error())
					}

					if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
						return nil, fmt.Errorf("cannot import rsa key: %s", jwkImportErr.Error())
					}
				} else if block.Type == "EC PRIVATE KEY" {
					key, loadErr := core.PrivateKeyFromBlock(block)
					if loadErr != nil {
						return nil, fmt.Errorf("cannot import elliptic-curve key bytes: %s", loadErr.Error())
					}

					if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
						return nil, fmt.Errorf("cannot import elliptic-curve key: %s", jwkImportErr.Error())
					}
				} else {
					return nil, fmt.Errorf("private key block %s import is not supported by Azure", block.Type)
				}
			}
		} else {
			// Else it must be a DER-encoded private key
			var key any
			var derLoadErr error

			if key, derLoadErr = x509.ParsePKCS8PrivateKey(keyData); derLoadErr != nil {
				password, passReadErr := inputReader("Private key requires password", keyParams.passwordFromFile, false, false)
				if passReadErr != nil {
					return nil, passReadErr
				}

				if key, derLoadErr = core.PrivateKeyFromDER(keyData, string(password)); derLoadErr != nil {
					return nil, fmt.Errorf("cannot load private key: %s", derLoadErr.Error())
				}
			}

			if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
				return nil, fmt.Errorf("cannot import rsa/escada key bytes: %s", jwkImportErr.Error())
			}
		}
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
	}
}

func OutputKeyTerraformCode(mdl KeyResourceTerraformModel, kwp *model.ContentWrappingParams, jwkKey interface{}) (string, error) {
	ciphertext, err := OutputKeyEncryptedContent(kwp, jwkKey)
	if err != nil {
		return ciphertext, err
	}

	mdl.EncryptedContent.SetValue(ciphertext)
	return model.Render("key", keyTFTemplate, &mdl)
}

func OutputKeyEncryptedContent(kwp *model.ContentWrappingParams, jwkKey interface{}) (string, error) {
	jwkData, marshalErr := json.Marshal(jwkKey)
	if marshalErr != nil {
		return "", marshalErr
	}

	kwp.ObjectType = keyvault.KeyObjectType
	helper := core.NewVersionedBinaryConfidentialDataHelper()
	_ = helper.CreateConfidentialBinaryData(jwkData, kwp.VersionedConfidentialMetadata)

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
