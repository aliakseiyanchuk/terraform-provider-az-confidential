package tfgen

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/stretchr/testify/assert"
	"testing"
)

func givenTypicalCertWrappingParams(t *testing.T) ContentWrappingParams {
	rv := givenTypicalKeyWrappingParameters(t)
	rv.TFBlockName = "cert"
	rv.DestinationCoordinate.Type = "certificate"

	return rv
}

func Test_Cert_EncodingPEMCertificate(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEM)

	output, err := GenerateConfidentialCertificateTerraformTemplate(
		givenTypicalCertWrappingParams(t),
		readMock.ReadInput,
		true,
		nil,
	)

	assert.Nil(t, err)
	fmt.Println(output)

	readMock.AssertExpectations(t)
}

func Test_Cert_EncodingPEMCertificateWithPasswordProtection(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEMWithEncryptedKey)
	readMock.GivenReadRequestReturnsString("Private key requires password", "s1cr3t")

	output, err := GenerateConfidentialCertificateTerraformTemplate(
		givenTypicalCertWrappingParams(t),
		readMock.ReadInput,
		true,
		nil,
	)

	assert.Nil(t, err)
	fmt.Println(output)

	readMock.AssertExpectations(t)
}

func Test_Cert_EncodingPEMCertificateErrsIfPasswordIsNotValid(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertificatePEMWithEncryptedKey)
	readMock.GivenReadRequestReturnsString("Private key requires password", "not-a-valid-s1cr3t")

	_, err := GenerateConfidentialCertificateTerraformTemplate(
		givenTypicalCertWrappingParams(t),
		readMock.ReadInput,
		true,
		nil,
	)

	assert.NotNil(t, err)
	assert.Equal(t, "pkcs8: incorrect password", err.Error())

	readMock.AssertExpectations(t)
}

func Test_Cert_EncodingDERCertificate(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertPFX12)
	readMock.GivenReadRequestReturnsString("Enter certificate password", "s1cr3t")

	output, err := GenerateConfidentialCertificateTerraformTemplate(
		givenTypicalCertWrappingParams(t),
		readMock.ReadInput,
		true,
		nil,
	)

	assert.Nil(t, err)
	fmt.Println(output)

	readMock.AssertExpectations(t)
}

func Test_Cert_EncodingDERCertificateWithWrongPassword(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter certificate data (hit Enter twice to end input)", testkeymaterial.EphemeralCertPFX12)
	readMock.GivenReadRequestReturnsString("Enter certificate password", "a-wrong-password")

	_, err := GenerateConfidentialCertificateTerraformTemplate(
		givenTypicalCertWrappingParams(t),
		readMock.ReadInput,
		true,
		nil,
	)

	assert.NotNil(t, err)
	assert.Equal(t, "cannot load certificate from PKCS12/PFX bag; pkcs12: decryption password incorrect", err.Error())

	readMock.AssertExpectations(t)
}
