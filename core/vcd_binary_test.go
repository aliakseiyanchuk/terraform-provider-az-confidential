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

	h := NewVersionedBinaryConfidentialDataHelper()
	origSecrt := h.CreateConfidentialBinaryData(buf, "example", nil)

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

	assert.Equal(t, cm.GetBinaryData(), origSecrt.GetBinaryData())
	assert.Equal(t, cm.GetLabels(), origSecrt.GetLabels())
	assert.Equal(t, cm.GetUUID(), origSecrt.GetUUID())
	assert.Equal(t, cm.GetType(), origSecrt.GetType())
}

func Test_VersionDataToEncryptedMessageConversionWithAESWithBase64(t *testing.T) {

	buf := make([]byte, 10240)
	_, err := rand.Read(buf)
	assert.Nil(t, err)

	h := NewVersionedBinaryConfidentialDataHelper()
	origSecrt := h.CreateConfidentialBinaryData(buf, "example", nil)

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

	cm, importErr := h.Import(plaintext)
	assert.Nil(t, importErr)

	assert.Equal(t, cm.GetBinaryData(), origSecrt.GetBinaryData())
	assert.Equal(t, cm.GetLabels(), origSecrt.GetLabels())
	assert.Equal(t, cm.GetUUID(), origSecrt.GetUUID())
	assert.Equal(t, cm.GetType(), origSecrt.GetType())
}
