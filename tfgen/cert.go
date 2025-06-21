// Copyright (c) HashiCorp, Inc.

package tfgen

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"golang.org/x/crypto/pkcs12"
)

const certCliArg = "cert"

//go:embed templates/cert_template.tmpl
var certTFTemplate string

var certCmd = flag.NewFlagSet(certCliArg, flag.ContinueOnError)

type CertTFGetParams struct {
	SecretTFGenParams

	certPasswordFile string
	noDERVerify      bool
}

var certParams = CertTFGetParams{}

func init() {
	certCmd.StringVar(&certParams.secretFromFile,
		"cert-file",
		"",
		"Read certificate from specified file")

	certCmd.StringVar(&certParams.certPasswordFile,
		"password-file",
		"",
		"Read password from specified file (for PKCS12 files)")

	certCmd.BoolVar(&certParams.secretInputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	certCmd.BoolVar(&certParams.noDERVerify,
		"no-der-verify",
		true,
		"Do not try parsing DER-encode files")
}

func GenerateConfidentialCertificateTerraformTemplate(kwp ContentWrappingParams, outputTFCOde bool, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	if parseErr := certCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	certData, readErr := ReadInput("Enter certificate data (hit Enter twice to end input)",
		certParams.secretFromFile,
		certParams.secretInputIsBase64,
		true)

	if readErr != nil {
		return "", readErr
	}

	certPass := ""

	if core.IsPEMEncoded(certData) {
		blocks, blockErr := core.ParsePEMBlocks(certData)
		if blockErr != nil {
			return "", fmt.Errorf("cannot parse PEM blocks: %s", blockErr.Error())
		}

		if len(core.FindCertificateBlocks(blocks)) == 0 {
			return "", errors.New("input does not contain any certificate blocks")
		}

		privateKeyBlock := core.FindPrivateKeyBlock(blocks)
		if privateKeyBlock == nil {
			return "", errors.New("input does not contain any private keys")
		}

		if privateKeyBlock.Type == "ENCRYPTED PRIVATE KEY" {
			password, passReadErr := ReadInput("Private key requires password", certParams.certPasswordFile, false, false)
			if passReadErr != nil {
				return "", passReadErr
			}

			// Try to decrypt the PEM key; to ensure that the password is correct
			_, loadErr := core.PrivateKeyFromEncryptedBlock(blocks[0], string(password))
			if loadErr != nil {
				return "", loadErr
			} else {
				certPass = string(password)
			}
		} else if privateKeyBlock.Type != "PRIVATE KEY" {
			return "", errors.New("input certificate data does not contain private key as first element")
		}
	} else {
		// Read the password for DER file
		var certPassBytes []byte
		var certPassErr error
		certPassBytes, certPassErr = ReadInput("Enter certificate password", certParams.certPasswordFile, false, false)
		if certPassErr != nil {
			return "", fmt.Errorf("cannot read certificate password: %s", certPassErr.Error())
		}

		vCerPass := string(certPassBytes)

		// Pass the DER file if no password verification is enabled, accept the passed data as-is
		if certParams.noDERVerify {
			certPass = string(certPassBytes)
		} else {
			// Try reading parsing certificate data
			if _, _, err := pkcs12.Decode(certData, ""); err != nil {
				if _, _, pwdErr := pkcs12.Decode(certData, vCerPass); pwdErr != nil {
					return "", fmt.Errorf("cannot decrypt certificate data: %s", pwdErr.Error())
				} else {
					certPass = vCerPass
				}
			}
		}
	}

	kwp.TFBlockNameIfUndefined("cert")

	if outputTFCOde {
		return OutputConfidentialCertificateTerraformCode(kwp, certData, certPass, nil)
	} else {
		return OutputCertificateEncryptedContent(kwp, certData, certPass)
	}
}

func OutputConfidentialCertificateTerraformCode(kwp ContentWrappingParams, data []byte, passwordString string, tags map[string]string) (string, error) {
	ciphertext, err := OutputCertificateEncryptedContent(kwp, data, passwordString)
	if err != nil {
		return ciphertext, err
	}

	rv := BaseTFTemplateParms{
		EncryptedContent: ciphertext,

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,

		TFBlockName: kwp.TFBlockName,

		Tags: tags,
	}

	return rv.Render("cert", certTFTemplate)
}

func OutputCertificateEncryptedContent(kwp ContentWrappingParams, data []byte, passwordString string) (string, error) {
	return OutputEncryptedConfidentialData(kwp, core.CreateDualConfidentialData(data, passwordString, "certificate", kwp.GetLabels()))
}
