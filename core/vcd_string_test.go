package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_VersionDataToEncryptedMessageConversion(t *testing.T) {
	h := NewVersionedStringConfidentialDataHelper()
	md := VersionedConfidentialMetadata{
		ObjectType: "example",
	}
	origSecret := h.CreateConfidentialStringData("this is a secret", md)

	// Perform forward conversion
	em, err := h.ToEncryptedMessage(LoadedEphemeralRsaPublicKey)
	assert.Nil(t, err)

	// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(LoadedEphemeralRsaPrivateKey, ciphertext, nil)
	}

	plaintext, decryptErr := em.ExtractPlainText(decrypter)
	assert.Nil(t, decryptErr)

	cm, importErr := h.ImportRaw(plaintext)
	assert.Nil(t, importErr)

	assert.Equal(t, cm.Data.GetStingData(), origSecret.Data.GetStingData())
	assert.Equal(t, cm.Header.ProviderConstraints, origSecret.Header.ProviderConstraints)
	assert.Equal(t, cm.Header.Uuid, origSecret.Header.Uuid)
	assert.Equal(t, cm.Header.Type, origSecret.Header.Type)
	assert.Equal(t, cm.Header.ModelReference, origSecret.Header.ModelReference)
}

func Test_VersionDataToEncryptedMessageConversionWithBase64(t *testing.T) {
	md := VersionedConfidentialMetadata{
		ObjectType: "example",
	}

	h := NewVersionedStringConfidentialDataHelper()
	origSecret := h.CreateConfidentialStringData("this is a secret", md)

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

	cm, importErr := h.ImportRaw(plaintext)
	assert.Nil(t, importErr)

	assert.Equal(t, cm.Data.GetStingData(), origSecret.Data.GetStingData())
	assert.Equal(t, cm.Header.ProviderConstraints, origSecret.Header.ProviderConstraints)
	assert.Equal(t, cm.Header.Uuid, origSecret.Header.Uuid)
	assert.Equal(t, cm.Header.Type, origSecret.Header.Type)
	assert.Equal(t, cm.Header.ModelReference, origSecret.Header.ModelReference)
}
