package keyvault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/io"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Key_OutputSecretTerraformCode_Renders(t *testing.T) {
	mdl, kwp := givenTypicalKeyWrappingParameters()

	jwkKey, jwkImportErr := jwk.Import(testkeymaterial.EphemeralRsaKeyText)
	assert.Nil(t, jwkImportErr)

	v, err := OutputKeyTerraformCode(
		mdl,
		&kwp,
		jwkKey)

	assert.Nil(t, err)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Print(v)
}

func givenTypicalKeyWrappingParameters() (KeyResourceTerraformModel, model.ContentWrappingParams) {

	kwp := model.ContentWrappingParams{
		VersionedConfidentialMetadata: core.VersionedConfidentialMetadata{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey:      core.LoadPublicKeyFromDataOnce(testkeymaterial.EphemeralRsaPublicKey),
		WrappingKeyCoordinate: model.NewWrappingKeyForExpressions("var.vault_name", "var.key_name", "var.key_version"),
	}

	keyModel := KeyResourceTerraformModel{
		TerraformCodeModel: TerraformCodeModel{
			BaseTerraformCodeModel: model.BaseTerraformCodeModel{
				TFBlockName:           "key",
				WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
			},

			TagsModel: model.TagsModel{
				IncludeTags: true,
				Tags: map[string]string{
					"foo":         "bar",
					"environment": "unit-test",
				},
			},

			DestinationCoordinate: NewObjectCoordinateModelUsingExpressions("var.dest_vault_name", "var.dest_object_name"),
		},
	}

	return keyModel, kwp
}

func Test_Key_ConvertSymmetricKey(t *testing.T) {
	sKey := make([]byte, 256/8)
	_, err := rand.Read(sKey)
	assert.Nil(t, err)

	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", sKey)

	_, cwp := givenTypicalKeyWrappingParameters()

	fn, err := MakeKeyGenerator(&cwp, "-symmetric")
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func assertGeneratorFunctionRendersSuccessfully(t *testing.T, cwp model.ContentWrappingParams, fn model.SubCommandExecution, readerMock *io.InputReaderMock) {
	tfCode, tfCodeErr := fn(readerMock.ReadInput, false)
	assert.Nil(t, tfCodeErr)
	assert.True(t, len(tfCode) > 100)

	if tfCodeErr != nil {
		fmt.Println(errors.Unwrap(tfCodeErr))
	}

	fmt.Println(tfCode)

	readerMock.AssertExpectations(t)
}

func assertGeneratorFunctionErrs(t *testing.T, cwp model.ContentWrappingParams, fn model.SubCommandExecution, readerMock *io.InputReaderMock) error {
	tfCode, tfCodeErr := fn(readerMock.ReadInput, false)
	assert.NotNil(t, tfCodeErr)
	assert.Equal(t, 0, len(tfCode))

	readerMock.AssertExpectations(t)

	return tfCodeErr
}

func Test_Key_ConvertSymmetricKey_ErrsOnUnsupportedLength(t *testing.T) {
	sKey := make([]byte, (256/8)-1)
	_, err := rand.Read(sKey)
	assert.Nil(t, err)

	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", sKey)

	_, cwp := givenTypicalKeyWrappingParameters()

	fn, err := MakeKeyGenerator(&cwp, "-symmetric")
	assert.Nil(t, err)

	_ = assertGeneratorFunctionErrs(t, cwp, fn, readMock)
}

func Test_Key_ConvertPEMEncodedRSAKey(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralRsaKeyText)

	_, cwp := givenTypicalKeyWrappingParameters()
	fn, err := MakeKeyGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Key_ConvertDEREncodedRSAKey(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralRsaKeyDERForm)

	_, cwp := givenTypicalKeyWrappingParameters()
	fn, err := MakeKeyGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Key_ConvertPEMEncodedECKey(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.Prime256v1EcPrivateKey)

	_, cwp := givenTypicalKeyWrappingParameters()
	fn, err := MakeKeyGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Key_ConvertPasswordProtectedPEMEncodedRSAKey(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralEncryptedRsaKeyText)
	readMock.GivenReadRequestReturns("Private key requires password", []byte("s1cr3t"))

	_, cwp := givenTypicalKeyWrappingParameters()
	fn, err := MakeKeyGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Key_ConvertPasswordProtectedDEREncodedRSAKey(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralEncryptedRsaKeyDERForm)
	readMock.GivenReadRequestReturns("Private key requires password", []byte("s1cr3t"))

	_, cwp := givenTypicalKeyWrappingParameters()
	fn, err := MakeKeyGenerator(&cwp)
	assert.Nil(t, err)

	assertGeneratorFunctionRendersSuccessfully(t, cwp, fn, readMock)
}

func Test_Key_ConvertPasswordProtectedPEMEncodedRSAKey_IfPasswordIsWrong(t *testing.T) {
	readMock := &io.InputReaderMock{}
	readMock.GivenReadRequestReturns("Enter key data (hit Enter twice to end input)", testkeymaterial.EphemeralEncryptedRsaKeyText)
	readMock.GivenReadRequestReturns("Private key requires password", []byte("wrong-s1cr3t"))

	_, cwp := givenTypicalKeyWrappingParameters()
	fn, err := MakeKeyGenerator(&cwp)
	assert.Nil(t, err)

	err = assertGeneratorFunctionErrs(t, cwp, fn, readMock)
	assert.NotNil(t, err)
	assert.Equal(t, "unable to load password-protected private key: pkcs8: incorrect password", err.Error())
}
