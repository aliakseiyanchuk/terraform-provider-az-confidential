package tfgen

import (
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const keyCliArg = "key"

//go:embed templates/key_template.tmpl
var keyTFTemplate string

type KeyTFGenParams struct {
	SecretTFGenParams

	passwordFromFile string
	symmetric        bool
}

func CreateKeyArgsParser() (*KeyTFGenParams, *flag.FlagSet) {
	keyParams := &KeyTFGenParams{}

	keyCmd := flag.NewFlagSet(keyCliArg, flag.ContinueOnError)

	keyCmd.StringVar(&keyParams.secretFromFile,
		"key-file",
		"",
		"Read key from specified file")

	keyCmd.StringVar(&keyParams.passwordFromFile,
		"password-file",
		"",
		"Read key password from file")

	keyCmd.BoolVar(&keyParams.secretInputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	keyCmd.BoolVar(&keyParams.symmetric,
		"symmetric",
		false,
		"Create symmetric key")

	return keyParams, keyCmd
}

func GenerateConfidentialKeyTerraformTemplate(kwp ContentWrappingParams, inputReader InputReader, outputTerraformCode bool, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	keyParams, keyCmd := CreateKeyArgsParser()

	if parseErr := keyCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	keyData, readErr := inputReader("Enter key data (hit Enter twice to end input)",
		keyParams.secretFromFile,
		keyParams.secretInputIsBase64,
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
				return "", fmt.Errorf("not a valid input: %s", blockErr.Error())
			} else {
				if block.Type == "ENCRYPTED PRIVATE KEY" {
					password, passReadErr := inputReader("Private key requires password", keyParams.passwordFromFile, false, false)
					if passReadErr != nil {
						return "", passReadErr
					}

					// Try to decrypt the PEM key
					key, loadErr := core.PrivateKeyFromEncryptedBlock(block, string(password))
					if loadErr != nil {
						return "", fmt.Errorf("unable to load password-protectedprivate key: %s", loadErr.Error())
					}

					if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
						return "", fmt.Errorf("cannot import rsa key bytes: %s", jwkImportErr.Error())
					}
				} else if block.Type == "PRIVATE KEY" {
					key, loadErr := core.PrivateKeyFromBlock(block)
					if loadErr != nil {
						return "", fmt.Errorf("cannot import rsa key bytes: %s", loadErr.Error())
					}

					if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
						return "", fmt.Errorf("cannot import rsa key: %s", jwkImportErr.Error())
					}
				} else if block.Type == "EC PRIVATE KEY" {
					key, loadErr := core.PrivateKeyFromBlock(block)
					if loadErr != nil {
						return "", fmt.Errorf("cannot import elliptic-curve key bytes: %s", loadErr.Error())
					}

					if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
						return "", fmt.Errorf("cannot import elliptic-curve key: %s", jwkImportErr.Error())
					}
				} else {
					return "", fmt.Errorf("private key block %s import is not supported by Azure", block.Type)
				}
			}
		} else {
			// Else it must be a DER-encoded private key
			var key any
			var derLoadErr error

			if key, derLoadErr = x509.ParsePKCS8PrivateKey(keyData); derLoadErr != nil {
				password, passReadErr := inputReader("Private key requires password", keyParams.passwordFromFile, false, false)
				if passReadErr != nil {
					return "", passReadErr
				}

				if key, derLoadErr = core.PrivateKeyFromDER(keyData, string(password)); derLoadErr != nil {
					return "", fmt.Errorf("cannot load private key: %s", derLoadErr.Error())
				}
			}

			if jwkKey, jwkImportErr = jwk.Import(key); jwkImportErr != nil {
				return "", fmt.Errorf("cannot import rsa/escada key bytes: %s", jwkImportErr.Error())
			}
		}
	}

	if jwkKey == nil {
		return "", fmt.Errorf("input was not converted to the JSON Web Key")
	}

	kwp.TFBlockNameIfUndefined("key")
	if outputTerraformCode {
		return OutputKeyTerraformCode(kwp, jwkKey, nil)
	} else {
		return OutputKeyEncryptedContent(kwp, jwkKey)
	}
}

type KeyTFTemplateParams struct {
	BaseTFTemplateParms

	KeyOperations []azkeys.KeyOperation
}

func (p *KeyTFTemplateParams) Render(templateName, templateStr string) (string, error) {
	return p.RenderObject(templateName, templateStr, p)
}

func (g *KeyTFTemplateParams) HasKeyOperations() bool {
	return len(g.KeyOperations) > 0
}

func OutputKeyTerraformCode(kwp ContentWrappingParams, jwkKey interface{}, tags map[string]string) (string, error) {
	ciphertext, err := OutputKeyEncryptedContent(kwp, jwkKey)
	if err != nil {
		return ciphertext, err
	}

	rv := KeyTFTemplateParams{
		BaseTFTemplateParms: BaseTFTemplateParms{
			EncryptedContent: ciphertext,
			Labels:           kwp.GetLabels(),

			TFBlockName: kwp.TFBlockName,

			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
			DestinationCoordinate: kwp.DestinationCoordinate,

			Tags: tags,
		},
	}

	if _, rsaOk := jwkKey.(jwk.RSAPrivateKey); rsaOk {
		rv.KeyOperations = []azkeys.KeyOperation{
			azkeys.KeyOperationEncrypt,
			azkeys.KeyOperationDecrypt,
			azkeys.KeyOperationSign,
			azkeys.KeyOperationVerify,
			azkeys.KeyOperationWrapKey,
			azkeys.KeyOperationUnwrapKey,
		}
	} else if _, ecOk := jwkKey.(jwk.ECDSAPrivateKey); ecOk {
		rv.KeyOperations = []azkeys.KeyOperation{
			azkeys.KeyOperationSign,
			azkeys.KeyOperationVerify,
		}
	}

	return rv.Render("key", keyTFTemplate)
}

func OutputKeyEncryptedContent(kwp ContentWrappingParams, jwkKey interface{}) (string, error) {
	jwkData, marshalErr := json.Marshal(jwkKey)
	if marshalErr != nil {
		return "", marshalErr
	}

	helper := core.NewVersionedBinaryConfidentialDataHelper()
	_ = helper.CreateConfidentialBinaryData(jwkData, "key", kwp.GetLabels())

	em, err := helper.ToEncryptedMessage(kwp.LoadedRsaPublicKey)
	if err != nil {
		return "", err
	}

	return em.ToBase64PEM(), nil
}
