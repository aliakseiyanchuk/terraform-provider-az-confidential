package keyvault

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/io"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func givenTypicalCertWrappingParams() (TerraformCodeModel, model.ContentWrappingParams) {

	kwp := model.ContentWrappingParams{
		VersionedConfidentialMetadata: core.VersionedConfidentialMetadata{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey:      core.LoadPublicKeyFromDataOnce(testkeymaterial.EphemeralRsaPublicKey),
		WrappingKeyCoordinate: model.NewWrappingKeyForExpressions("var.vault_name", "var.key_name", "var.key_version"),
	}

	mdl := TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "cert",
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		TagsModel: model.TagsModel{
			IncludeTags: false,
		},
	}

	return mdl, kwp
}

func Test_Cert_EncodingPEMCertificate(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEM)

	_, cwp := givenTypicalCertWrappingParams()
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Cert_EncodingPEMCertificateWithPasswordProtection(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEMWithEncryptedKey)
	readMock.GivenReadRequestReturnsString("Private key requires password", "s1cr3t")

	_, cwp := givenTypicalKeyWrappingParameters()
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Cert_EncodingPEMCertificateErrsIfPasswordIsNotValid(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEMWithEncryptedKey)
	readMock.GivenReadRequestReturnsString("Private key requires password", "not-a-valid-s1cr3t")

	_, cwp := givenTypicalCertWrappingParams()
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	err = assertGeneratorFunctionErrs(t, cwp, fn, readMock)
	if err != nil {
		assert.Equal(t, "pkcs8: incorrect password", err.Error())
	} else {
		assert.Fail(t, "expected error, got nil")
	}
}

func Test_Cert_EncodingDERCertificate(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertPFX12)
	readMock.GivenReadRequestReturnsString("Enter certificate password", "s1cr3t")

	_, cwp := givenTypicalCertWrappingParams()
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Cert_EncodingDERCertificateWithWrongPassword(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertPFX12)
	readMock.GivenReadRequestReturnsString("Enter certificate password", "a-wrong-password")

	_, cwp := givenTypicalCertWrappingParams()
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	err = assertGeneratorFunctionErrs(t, cwp, fn, readMock)
	if err != nil {
		assert.Equal(t, "cannot load certificate from PKCS12/PFX bag; pkcs12: decryption password incorrect", err.Error())
	} else {
		assert.Fail(t, "expected error, got nil")
	}
}
