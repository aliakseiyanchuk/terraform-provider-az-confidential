package keyvault

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/io"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func givenTypicalCertWrappingParams(t *testing.T) (TerraformCodeModel, model.ContentWrappingParams) {
	rsaKey, rsaLoadErr := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.Nil(t, rsaLoadErr)

	kwp := model.ContentWrappingParams{
		Labels:                []string{"acceptance-testing"},
		LoadedRsaPublicKey:    rsaKey,
		WrappingKeyCoordinate: model.NewWrappingKeyForExpressions("var.vault_name", "var.key_name", "var.key_version"),
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
	}

	return mdl, kwp
}

func Test_Cert_EncodingPEMCertificate(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEM)

	_, cwp := givenTypicalCertWrappingParams(t)
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Cert_EncodingPEMCertificateWithPasswordProtection(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEMWithEncryptedKey)
	readMock.GivenReadRequestReturnsString("Private key requires password", "s1cr3t")

	_, cwp := givenTypicalKeyWrappingParameters(t)
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Cert_EncodingPEMCertificateErrsIfPasswordIsNotValid(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEMWithEncryptedKey)
	readMock.GivenReadRequestReturnsString("Private key requires password", "not-a-valid-s1cr3t")

	_, cwp := givenTypicalCertWrappingParams(t)
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

	_, cwp := givenTypicalCertWrappingParams(t)
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Cert_EncodingDERCertificateWithWrongPassword(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertPFX12)
	readMock.GivenReadRequestReturnsString("Enter certificate password", "a-wrong-password")

	_, cwp := givenTypicalCertWrappingParams(t)
	fn, err := MakeCertGenerator(&cwp)
	assert.Nil(t, err)

	err = assertGeneratorFunctionErrs(t, cwp, fn, readMock)
	if err != nil {
		assert.Equal(t, "cannot load certificate from PKCS12/PFX bag; pkcs12: decryption password incorrect", err.Error())
	} else {
		assert.Fail(t, "expected error, got nil")
	}
}
