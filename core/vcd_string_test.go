package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_VersionDataToEncryptedMessageConversion(t *testing.T) {
	h := NewVersionedStringConfidentialDataHelper()
	origSecret := h.CreateConfidentialStringData("this is a secret", "example", nil)

	// Perform forward conversion
	em, err := h.ToEncryptedMessage(LoadedEphemeralRsaPublicKey)
	assert.Nil(t, err)

	// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(LoadedEphemeralRsaPrivateKey, ciphertext, nil)
	}

	plaintext, decryptErr := em.ExtractPlainText(decrypter)
	assert.Nil(t, decryptErr)

	cm, importErr := h.Import(plaintext)
	assert.Nil(t, importErr)

	assert.Equal(t, cm.GetStingData(), origSecret.GetStingData())
	assert.Equal(t, cm.GetLabels(), origSecret.GetLabels())
	assert.Equal(t, cm.GetUUID(), origSecret.GetUUID())
	assert.Equal(t, cm.GetType(), origSecret.GetType())
}

func Test_VersionDataToEncryptedMessageConversionWithBase64(t *testing.T) {
	h := NewVersionedStringConfidentialDataHelper()
	origSecret := h.CreateConfidentialStringData("this is a secret", "example", nil)

	// Perform forward conversion
	em, err := h.ToEncryptedMessage(LoadedEphemeralRsaPublicKey)
	assert.Nil(t, err)

	emAtRest := em.ToBase64PEM()

	rbEm := EncryptedMessage{}
	rbErr := rbEm.FromBase64PEM(emAtRest)
	assert.Nil(t, rbErr)

	/// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(LoadedEphemeralRsaPrivateKey, ciphertext, nil)
	}

	plaintext, decryptErr := em.ExtractPlainText(decrypter)
	assert.Nil(t, decryptErr)

	cm, importErr := h.Import(plaintext)
	assert.Nil(t, importErr)

	assert.Equal(t, cm.GetStingData(), origSecret.GetStingData())
	assert.Equal(t, cm.GetLabels(), origSecret.GetLabels())
	assert.Equal(t, cm.GetUUID(), origSecret.GetUUID())
	assert.Equal(t, cm.GetType(), origSecret.GetType())
}
