package keyvault

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

//go:embed cert_template.tmpl
var certTFTemplate string

type CertTFGenParams struct {
	KeyVaultGroupCLIParams

	certPasswordFile string
	noDERVerify      bool
}

const (
	CertFormatPem    = "application/x-pem-file"
	CertFormatPkcs12 = "application/x-pkcs12"
)

func CreateCertArgsParser() (*CertTFGenParams, *flag.FlagSet) {
	var certParams = CertTFGenParams{}

	var certCmd = flag.NewFlagSet("cert", flag.ExitOnError)

	certCmd.StringVar(&certParams.inputFile,
		"cert-file",
		"",
		"Read certificate from specified file")

	certCmd.StringVar(&certParams.certPasswordFile,
		"password-file",
		"",
		"Read password from specified file (for PKCS12 files)")

	certCmd.BoolVar(&certParams.inputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	certCmd.BoolVar(&certParams.noDERVerify,
		"no-der-verify",
		false,
		"Do not try parsing DER-encode files")

	certCmd.StringVar(&certParams.vaultName,
		"destination-vault",
		"",
		"Destination vault name")

	certCmd.StringVar(&certParams.vaultObjectName,
		"destination-cert-name",
		"",
		"Destination certificate name")

	return &certParams, certCmd
}

func MakeCertGenerator(kwp *model.ContentWrappingParams, args ...string) (model.SubCommandExecution, error) {
	certParams, certCmd := CreateCertArgsParser()

	if parseErr := certCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	if kwp.AddTargetLabel {
		if !certParams.SpecifiesVault() {
			return nil, errors.New("options -destination-vault and -destination-cert-name must be supplied where ciphertext must be labelled with its intended destination")
		} else {
			coord := core.AzKeyVaultObjectCoordinate{
				VaultName: certParams.vaultName,
				Name:      certParams.vaultObjectName,
				Type:      "certificates",
			}

			kwp.AddLabel(coord.GetLabel())
		}
	}

	mdl := TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "cert",
			CiphertextLabels:      kwp.GetLabels(),
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		TagsModel: model.TagsModel{
			IncludeTags: false,
		},

		DestinationCoordinate: NewObjectCoordinateModel(certParams.vaultName, certParams.vaultObjectName),

		NotBeforeExample: model.NotBeforeExample(),
		NotAfterExample:  model.NotAfterExample(),
	}

	fmt.Println(mdl.DestinationCoordinate.VaultName.TerraformExpression())
	fmt.Println(mdl.DestinationCoordinate.VaultName.IsDefined())
	fmt.Println(mdl.DestinationCoordinate.ObjectName.TerraformExpression())

	return func(kwp model.ContentWrappingParams, inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		certData, certDataErr := AcquireCertificateData(certParams, inputReader)
		if certDataErr != nil {
			return "", certDataErr
		}

		if onlyCiphertext {
			return OutputCertificateEncryptedContent(kwp, certData)
		} else {
			return OutputCertificateTerraformCode(mdl, kwp, certData)
		}
	}, nil
}

func AcquireCertificateData(certParams *CertTFGenParams, inputReader model.InputReader) (core.ConfidentialCertificateData, error) {
	certData, readErr := inputReader("Enter certificate data (hit Enter twice to end input)",
		certParams.inputFile,
		certParams.inputIsBase64,
		true)

	if readErr != nil {
		return nil, readErr
	}

	confData := core.ConfidentialCertConfidentialDataStruct{
		CertificateData:         certData,
		CertificateDataFormat:   "application/unknown",
		CertificateDataPassword: "",
	}

	if core.IsPEMEncoded(certData) {
		confData.CertificateDataFormat = CertFormatPem

		blocks, blockErr := core.ParsePEMBlocks(certData)
		if blockErr != nil {
			return nil, fmt.Errorf("cannot parse PEM blocks: %s", blockErr.Error())
		}

		if len(core.FindCertificateBlocks(blocks)) == 0 {
			return nil, errors.New("input does not contain any certificate blocks")
		}

		privateKeyBlock := core.FindPrivateKeyBlock(blocks)
		if privateKeyBlock == nil {
			return nil, errors.New("input does not contain any private keys")
		}

		if privateKeyBlock.Type == "ENCRYPTED PRIVATE KEY" {
			password, passReadErr := inputReader("Private key requires password", certParams.certPasswordFile, false, false)
			if passReadErr != nil {
				return nil, passReadErr
			}

			// Try to decrypt the PEM key; to ensure that the password is correct
			_, loadErr := core.PrivateKeyFromEncryptedBlock(blocks[0], string(password))
			if loadErr != nil {
				return nil, loadErr
			} else {
				confData.CertificateDataPassword = string(password)
			}
		} else if privateKeyBlock.Type != "PRIVATE KEY" {
			return nil, errors.New("input certificate data does not contain private key")
		}
	} else {
		confData.CertificateDataFormat = CertFormatPkcs12

		var certPassBytes []byte
		var certPassErr error
		certPassBytes, certPassErr = inputReader("Enter certificate password", certParams.certPasswordFile, false, false)
		if certPassErr != nil {
			return nil, fmt.Errorf("cannot read certificate password: %s", certPassErr.Error())
		}

		if certParams.noDERVerify {
			confData.CertificateDataPassword = string(certPassBytes)
		} else {
			// Try reading parsing certificate data
			if _, _, pwdErr := pkcs12.Decode(certData, string(certPassBytes)); pwdErr != nil {
				return nil, fmt.Errorf("cannot load certificate from PKCS12/PFX bag; %s", pwdErr.Error())
			}
		}
	}

	return &confData, nil
}

func OutputCertificateTerraformCode(mdl TerraformCodeModel, kwp model.ContentWrappingParams, data core.ConfidentialCertificateData) (string, error) {
	ciphertext, err := OutputCertificateEncryptedContent(kwp, data)
	if err != nil {
		return ciphertext, err
	}

	mdl.EncryptedContent.SetValue(ciphertext)
	return model.Render("cert", certTFTemplate, &mdl)
}

func OutputCertificateEncryptedContent(kwp model.ContentWrappingParams, data core.ConfidentialCertificateData) (string, error) {
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper()
	_ = helper.CreateConfidentialCertificateData(
		data.GetCertificateData(),
		data.GetCertificateDataFormat(),
		data.GetCertificateDataPassword(),
		keyvault.CertificateObjectType,
		kwp.GetLabels(),
	)

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
