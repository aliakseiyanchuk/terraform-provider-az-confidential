package core

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_VersionDataToEncryptedMessageConversionWithAES(t *testing.T) {

	buf := make([]byte, 10240)
	_, err := rand.Read(buf)
	assert.Nil(t, err)

	md := SecondaryProtectionParameters{}

	h := NewVersionedBinaryConfidentialDataHelper("example")
	origSecret := h.CreateConfidentialBinaryData(buf, md)

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

	assert.Equal(t, cm.Data.GetBinaryData(), origSecret.Data.GetBinaryData())
	assert.Equal(t, cm.Header.ProviderConstraints, origSecret.Header.ProviderConstraints)
	assert.Equal(t, cm.Header.Uuid, origSecret.Header.Uuid)
	assert.Equal(t, cm.Header.Type, origSecret.Header.Type)
	assert.Equal(t, cm.Header.ModelReference, origSecret.Header.ModelReference)
}

func Test_VersionDataToEncryptedMessageConversionWithAESWithBase64(t *testing.T) {

	buf := make([]byte, 10240)
	_, err := rand.Read(buf)
	assert.Nil(t, err)

	md := SecondaryProtectionParameters{}

	h := NewVersionedBinaryConfidentialDataHelper("example")
	origSecret := h.CreateConfidentialBinaryData(buf, md)

	// Perform forward conversion
	em, err := h.ToEncryptedMessage(LoadedEphemeralRsaPublicKey)
	assert.Nil(t, err)

	emAtRest := em.ToBase64PEM()

	rbEm := EncryptedMessage{}
	rbErr := rbEm.FromBase64PEM(emAtRest)
	assert.Nil(t, rbErr)

	// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(LoadedEphemeralRsaPrivateKey, ciphertext, nil)
	}

	plaintext, decryptErr := em.ExtractPlainText(decrypter)
	assert.Nil(t, decryptErr)

	cm, importErr := h.ImportRaw(plaintext)
	assert.Nil(t, importErr)

	assert.Equal(t, cm.Data.GetBinaryData(), origSecret.Data.GetBinaryData())
	assert.Equal(t, cm.Header.ProviderConstraints, origSecret.Header.ProviderConstraints)
	assert.Equal(t, cm.Header.Uuid, origSecret.Header.Uuid)
	assert.Equal(t, cm.Header.Type, origSecret.Header.Type)
	assert.Equal(t, cm.Header.ModelReference, origSecret.Header.ModelReference)
}
