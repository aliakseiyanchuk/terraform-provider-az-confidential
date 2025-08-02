package keyvault

import (
	_ "embed"
	"errors"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
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
		DestinationVaultCliOption.String(),
		"",
		"Destination vault name")

	certCmd.StringVar(&certParams.vaultObjectName,
		DestinationVaultCertificateCliOption.String(),
		"",
		"Destination certificate name")

	return &certParams, certCmd
}

func MakeCertGenerator(kwp *model.ContentWrappingParams, args ...string) (model.SubCommandExecution, error) {
	certParams, certCmd := CreateCertArgsParser()

	if parseErr := certCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	if kwp.LockPlacement && !certParams.SpecifiesVault() {
		return nil, errors.New("options -destination-vault and -destination-cert-name must be supplied where ciphertext must be labelled with its intended destination")
	}

	mdl := TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "cert",
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		TagsModel: model.TagsModel{
			IncludeTags: false,
		},

		DestinationCoordinate: NewObjectCoordinateModel(certParams.vaultName, certParams.vaultObjectName),

		NotBeforeExample: model.NotBeforeExample(),
		NotAfterExample:  model.NotAfterExample(),
	}

	return func(inputReader model.InputReader) (model.TerraformCode, core.EncryptedMessage, error) {
		certData, certDataErr := AcquireCertificateData(certParams, inputReader)
		if certDataErr != nil {
			return "", core.EncryptedMessage{}, certDataErr
		}

		return OutputCertificateTerraformCode(mdl, kwp, certData)
	}, nil
}

func CertificateNeedsPassword(certData []byte) bool {
	if !core.IsPEMEncoded(certData) {
		return true
	}
	if blocks, pemErr := core.ParsePEMBlocks(certData); pemErr != nil {
		return true
	} else {
		privateKeyBlock := core.FindPrivateKeyBlock(blocks)
		return privateKeyBlock.Type == "ENCRYPTED PRIVATE KEY"
	}
}

func AcquireCertificateData(certParams *CertTFGenParams, inputReader model.InputReader) (core.ConfidentialCertificateData, error) {
	certData, readErr := inputReader(CertificateDataPrompt,
		certParams.inputFile,
		certParams.inputIsBase64,
		true)

	if readErr != nil {
		return nil, readErr
	}

	password := ""
	if CertificateNeedsPassword(certData) {
		if p, passReadErr := inputReader(CertificatePasswordPrompt, certParams.certPasswordFile, false, false); passReadErr != nil {
			return nil, passReadErr
		} else {
			password = string(p)
		}
	}

	return keyvault.AcquireCertificateData(certData, password)

}

func OutputCertificateTerraformCode(mdl TerraformCodeModel, kwp *model.ContentWrappingParams, data core.ConfidentialCertificateData) (model.TerraformCode, core.EncryptedMessage, error) {
	em, params, err := makeCertificateEncryptedMessage(mdl, kwp, data)
	if err != nil {
		return "", em, err
	}

	mdl.EncryptedContent.SetValue(model.Ciphertext(em.ToBase64PEM()))
	mdl.EncryptedContentMetadata = kwp.GetMetadataForTerraformFor(params, "keyvault certificate", "destination_certificate")
	mdl.EncryptedContentMetadata.ResourceHasDestination = true

	tfCode, tfCodeErr := model.Render("cert", certTFTemplate, &mdl)
	return tfCode, em, tfCodeErr
}

func makeCertificateEncryptedMessage(mdl TerraformCodeModel, kwp *model.ContentWrappingParams, data core.ConfidentialCertificateData) (core.EncryptedMessage, core.SecondaryProtectionParameters, error) {
	rsaKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return core.EncryptedMessage{}, kwp.SecondaryProtectionParameters, rsaKeyErr
	}

	var lockCoord *core.AzKeyVaultObjectCoordinate
	if kwp.LockPlacement {
		lockCoord = &core.AzKeyVaultObjectCoordinate{
			VaultName: mdl.DestinationCoordinate.VaultName.Value,
			Name:      mdl.DestinationCoordinate.ObjectName.Value,
			Type:      "certificates",
		}
	}

	em, md, emErr := keyvault.CreateCertificateEncryptedMessage(data, lockCoord, kwp.SecondaryProtectionParameters, rsaKey)
	return em, md, emErr
}
