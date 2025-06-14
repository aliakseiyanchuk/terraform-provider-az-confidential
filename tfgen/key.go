package main

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

const keyCliArg = "key"

//go:embed key_template.tmpl
var keyTFTemplate string

var keyCmd = flag.NewFlagSet(keyCliArg, flag.ContinueOnError)

type KeyTFGetParams struct {
	SecretTFGenParams

	passwordFromFile string
	symmetric        bool
}

var keyParams = KeyTFGetParams{}

func init() {
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
}

func generateConfidentialKeyTerraformTemplate(kwp KeyWrappingParams, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	if parseErr := keyCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	keyData, readErr := ReadInput("Enter key data (hit Enter twice to end input)",
		keyParams.secretFromFile,
		keyParams.secretInputIsBase64,
		true)

	if readErr != nil {
		return "", readErr
	}

	objType := "key"
	if keyParams.symmetric {
		objType = "symmetric-key"

		bits := len(keyData) * 8
		if bits != 128 && bits != 192 && bits != 256 {
			return "", fmt.Errorf("invalid symmetric key length: only 128, 192, and 256 bits are allowed, but %d was supplied", bits)
		}

	} else {
		if core.IsPEMEncoded(keyData) {
			if block, blockErr := core.ParseSinglePEMBlock(keyData); blockErr != nil {
				return "", fmt.Errorf("not a valid input: %s", blockErr.Error())
			} else {
				if block.Type == "ENCRYPTED PRIVATE KEY" {
					password, passReadErr := ReadInput("Private key requires password", keyParams.passwordFromFile, false, false)
					if passReadErr != nil {
						return "", passReadErr
					}

					// Try to decrypt the PEM key
					key, loadErr := core.PrivateKeyFromEncryptedBlock(block, string(password))
					if loadErr != nil {
						return "", loadErr
					}

					if mKeyData, marshalErr := x509.MarshalPKCS8PrivateKey(key); marshalErr != nil {
						return "", marshalErr
					} else {
						keyData = mKeyData
					}
				} else if block.Type != "PRIVATE KEY" {
					return "", fmt.Errorf("private key block %s import is not supported by Azure", block.Type)
				}
			}
		} else {
			// Else it must be a DER-encoded private key
			var key any
			var derLoadErr error
			if key, derLoadErr = x509.ParsePKCS8PrivateKey(keyData); derLoadErr != nil {
				password, passReadErr := ReadInput("Private key requires password", keyParams.passwordFromFile, false, false)
				if passReadErr != nil {
					return "", passReadErr
				}

				if key, derLoadErr = core.PrivateKeyFromDER(keyData, string(password)); derLoadErr != nil {
					return "", fmt.Errorf("cannot load private key: %s", derLoadErr.Error())
				} else {
					// The Following code decrypts the private key bytes for addition into the payload.
					if mKeyData, marshalErr := x509.MarshalPKCS8PrivateKey(key); marshalErr != nil {
						return "", marshalErr
					} else {
						keyData = mKeyData
					}
				}
			}

			// Ensure that the key passed is an RSA key.
			if _, ok := key.(*rsa.PrivateKey); !ok {
				return "", errors.New("incorrect private key type")
			}
		}
	}

	payloadBytes := core.WrapBinaryPayload(keyData, objType, kwp.GetLabels())

	// Ensure that the provider code will be able to make out a SON Web Key out of the data
	// supplied.

	if payload, unwrapErr := core.UnwrapPayload(payloadBytes); unwrapErr != nil {
		return "", fmt.Errorf("internal problem: the key would not be unwrapped correctly: %s, Please report this problem", unwrapErr.Error())
	} else {
		outKey := azkeys.JSONWebKey{}
		if convErr := core.PrivateKeyTOJSONWebKey(payload.Payload, "", &outKey); convErr != nil {
			return "", fmt.Errorf("insufficient material to build JSON Web Key: %s, Please report this problem", convErr.Error())
		}
	}

	// Creation of the payload has succeeded.
	em, emErr := core.CreateEncryptedMessage(kwp.loadedRsaPublicKey, payloadBytes)
	if emErr != nil {
		return "", emErr
	}

	rv := BaseTFTemplateParms{
		EncryptedContent:     em.GetSecretExpr(),
		ContentEncryptionKey: em.GetContentEncryptionKeyExpr(),

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,
	}

	return rv.Render("key", keyTFTemplate)
}
