package tfgen

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const certCliArg = "cert"

//go:embed templates/cert_template.tmpl
var certTFTemplate string

type CertTFGenParams struct {
	SecretTFGenParams

	certPasswordFile string
	noDERVerify      bool
}

const (
	CERT_FORMAT_PEM    = "application/x-pem-file"
	CERT_FORMAT_PKCS12 = "application/x-pkcs12"
)

func CreateCertArgsParser() (*CertTFGenParams, *flag.FlagSet) {
	var certParams = CertTFGenParams{}

	var certCmd = flag.NewFlagSet(certCliArg, flag.ContinueOnError)

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
		false,
		"Do not try parsing DER-encode files")

	return &certParams, certCmd
}

func GenerateConfidentialCertificateTerraformTemplate(kwp ContentWrappingParams, inputReader InputReader, outputTFCOde bool, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	certParams, certCmd := CreateCertArgsParser()

	if parseErr := certCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	certData, readErr := inputReader("Enter certificate data (hit Enter twice to end input)",
		certParams.secretFromFile,
		certParams.secretInputIsBase64,
		true)

	if readErr != nil {
		return "", readErr
	}

	certPass := ""
	certFormat := "application/unknown"

	if core.IsPEMEncoded(certData) {
		certFormat = CERT_FORMAT_PEM

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
			password, passReadErr := inputReader("Private key requires password", certParams.certPasswordFile, false, false)
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
			return "", errors.New("input certificate data does not contain private key")
		}
	} else {
		certFormat = CERT_FORMAT_PKCS12

		var certPassBytes []byte
		var certPassErr error
		certPassBytes, certPassErr = inputReader("Enter certificate password", certParams.certPasswordFile, false, false)
		if certPassErr != nil {
			return "", fmt.Errorf("cannot read certificate password: %s", certPassErr.Error())
		}

		if certParams.noDERVerify {
			certPass = string(certPassBytes)
		} else {
			// Try reading parsing certificate data
			if _, _, pwdErr := pkcs12.Decode(certData, string(certPassBytes)); pwdErr != nil {
				return "", fmt.Errorf("cannot load certificate from PKCS12/PFX bag; %s", pwdErr.Error())
			}
		}
	}

	kwp.TFBlockNameIfUndefined("cert")

	if outputTFCOde {
		return OutputConfidentialCertificateTerraformCode(kwp, certData, certFormat, certPass, nil)
	} else {
		return OutputCertificateEncryptedContent(kwp, certData, certFormat, certPass)
	}
}

func OutputConfidentialCertificateTerraformCode(kwp ContentWrappingParams, data []byte, certFormat, passwordString string, tags map[string]string) (string, error) {
	ciphertext, err := OutputCertificateEncryptedContent(kwp, data, certFormat, passwordString)
	if err != nil {
		return ciphertext, err
	}

	rv := BaseTFTemplateParms{
		EncryptedContent: ciphertext,
		Labels:           kwp.GetLabels(),

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,

		TFBlockName: kwp.TFBlockName,

		Tags: tags,
	}

	return rv.Render("cert", certTFTemplate)
}

func OutputCertificateEncryptedContent(kwp ContentWrappingParams, data []byte, certFormat string, passwordString string) (string, error) {
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper()
	_ = helper.CreateConfidentialCertificateData(
		data,
		certFormat,
		passwordString,
		"certificate",
		kwp.GetLabels(),
	)

	em, err := helper.ToEncryptedMessage(kwp.LoadedRsaPublicKey)
	if err != nil {
		return "", err
	}

	return em.ToBase64PEM(), nil
}
