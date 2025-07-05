package tfgen

import (
	"crypto/rand"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Key_OutputSecretTerraformCode_Renders(t *testing.T) {
	kwp := givenTypicalKeyWrappingParameters(t)

	jwkKey, jwkImportErr := jwk.Import(testkeymaterial.EphemeralRsaKeyText)
	assert.Nil(t, jwkImportErr)

	v, err := OutputKeyTerraformCode(kwp,
		jwkKey,
		basicTags)

	assert.Nil(t, err)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Print(v)
}

func givenTypicalKeyWrappingParameters(t *testing.T) ContentWrappingParams {
	rsaKey, rsaLoadErr := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.Nil(t, rsaLoadErr)

	kwp := ContentWrappingParams{
		LoadedRsaPublicKey: rsaKey,
		DestinationCoordinate: AzKeyVaultObjectCoordinateTFCode{
			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
				VaultName: "var.dest_vault_name",
				Name:      "var.dest_object_name",
				Type:      "secret",
			},
			VaultNameIsExpr:  true,
			ObjectNameIsExpr: true,
		},
		WrappingKeyCoordinate: WrappingKeyCoordinateTFCode{
			WrappingKeyCoordinate: core.WrappingKeyCoordinate{
				VaultName:  "var.vault_name",
				KeyName:    "var.key_name",
				KeyVersion: "var.key_version",
			},
			KeyNameIsExpr:    true,
			VaultNameIsExpr:  true,
			KeyVersionIsExpr: true,
		},

		TFBlockName: "key",
	}
	return kwp
}

func Test_Key_ConvertSymmetricKey(t *testing.T) {
	sKey := make([]byte, 256/8)
	_, err := rand.Read(sKey)
	assert.Nil(t, err)

	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", sKey)

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err = GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{"-symmetric"})
	assert.Nil(t, err)

	readMock.AssertExpectations(t)
}

func Test_Key_ConvertSymmetricKey_ErrsOnUnsupportedLength(t *testing.T) {
	sKey := make([]byte, (256/8)-1)
	_, err := rand.Read(sKey)
	assert.Nil(t, err)

	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", sKey)

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err = GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{"-symmetric"})
	assert.NotNil(t, err)

	readMock.AssertExpectations(t)
}

func Test_Key_ConvertPEMEncodedRSAKey(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralRsaKeyText)

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err := GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{})
	assert.Nil(t, err)

	readMock.AssertExpectations(t)
}

func Test_Key_ConvertDEREncodedRSAKey(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralRsaKeyDERForm)

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err := GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{})
	assert.Nil(t, err)

	readMock.AssertExpectations(t)
}

func Test_Key_ConvertPEMEncodedECKey(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.Prime256v1EcPrivateKey)

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err := GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{})
	assert.Nil(t, err)

	readMock.AssertExpectations(t)
}

func Test_Key_ConvertPasswordProtectedPEMEncodedRSAKey(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralEncryptedRsaKeyText)
	readMock.GivenReadRequestReturns("Private key requires password", []byte("s1cr3t"))

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err := GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{})
	assert.Nil(t, err)

	readMock.AssertExpectations(t)
}

func Test_Key_ConvertPasswordProtectedDEREncodedRSAKey(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralEncryptedRsaKeyDERForm)
	readMock.GivenReadRequestReturns("Private key requires password", []byte("s1cr3t"))

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err := GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{})
	assert.Nil(t, err)

	readMock.AssertExpectations(t)
}

func Test_Key_ConvertPasswordProtectedPEMEncodedRSAKey_IfPasswordIsWrong(t *testing.T) {
	readMock := &InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralEncryptedRsaKeyText)
	readMock.GivenReadRequestReturns("Private key requires password", []byte("wrong-s1cr3t"))

	cwp := givenTypicalKeyWrappingParameters(t)

	_, err := GenerateConfidentialKeyTerraformTemplate(cwp, readMock.ReadInput, true, []string{})
	assert.NotNil(t, err)

	readMock.AssertExpectations(t)
}
