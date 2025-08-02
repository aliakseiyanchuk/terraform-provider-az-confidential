package tfgen

import (
	"crypto/rsa"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/io"
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
	"time"
)

func assertDaysInFuture(t *testing.T, days int, epochSecond int64) {
	timeInFuture := time.Unix(epochSecond, 0)

	exp := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	diff := exp.Sub(timeInFuture)

	assert.True(t, math.Abs(float64(diff)) < float64(time.Hour))
}

func assertHoursInFuture(t *testing.T, hours int, epochSecond int64) {
	timeInFuture := time.Unix(epochSecond, 0)

	exp := time.Now().Add(time.Duration(hours) * time.Hour)
	diff := exp.Sub(timeInFuture)

	assert.True(t, math.Abs(float64(diff)) < float64(time.Minute))
}

func givenSetup(t *testing.T) (core.RSADecrypter, *io.InputReaderMock) {
	rsaPriv, keyErr := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, keyErr)

	mock := &io.InputReaderMock{}
	mock.GivenReadRequestReturns(PublicKeyPrompt, testkeymaterial.EphemeralRsaPublicKey)

	return func(bytes []byte) ([]byte, error) {
		return core.RsaDecryptBytes(rsaPriv.(*rsa.PrivateKey), bytes, nil)
	}, mock
}
