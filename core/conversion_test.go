package core

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_VersionDataToEncryptedMessageConversion(t *testing.T) {
	cm := CreateConfidentialStringData("this is a secret", "example", nil)
	privateKey, publicKey := GenerateEphemeralKeyPair()

	// Perform forward conversion
	em, err := ConvertConfidentialDataToEncryptedMessage(cm, publicKey)
	assert.Nil(t, err)

	// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(privateKey, ciphertext, nil)
	}

	rvCm, rvErr := ConvertEncryptedMessageToConfidentialData(em, decrypter)
	assert.Nil(t, rvErr)

	assert.Equal(t, cm.BinaryData, rvCm.BinaryData)
	assert.Equal(t, cm.StringData, rvCm.StringData)
	assert.Equal(t, cm.Labels, rvCm.Labels)
	assert.Equal(t, cm.Uuid, rvCm.Uuid)
	assert.Equal(t, cm.Type, rvCm.Type)
}

func Test_VersionDataToEncryptedMessageConversionWithAES(t *testing.T) {

	buf := make([]byte, 10240)
	_, err := rand.Read(buf)
	assert.Nil(t, err)

	cm := CreateConfidentialBinaryData(buf, "example", nil)
	privateKey, publicKey := GenerateEphemeralKeyPair()

	// Perform forward conversion
	em, err := ConvertConfidentialDataToEncryptedMessage(cm, publicKey)
	assert.Nil(t, err)

	// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(privateKey, ciphertext, nil)
	}

	rvCm, rvErr := ConvertEncryptedMessageToConfidentialData(em, decrypter)
	assert.Nil(t, rvErr)

	assert.Equal(t, cm.BinaryData, rvCm.BinaryData)
	assert.Equal(t, cm.StringData, rvCm.StringData)
	assert.Equal(t, cm.Labels, rvCm.Labels)
	assert.Equal(t, cm.Uuid, rvCm.Uuid)
	assert.Equal(t, cm.Type, rvCm.Type)
}

func Test_VersionDataToEncryptedMessageConversionWithBase64(t *testing.T) {
	cm := CreateConfidentialStringData("this is a secret", "example", nil)
	privateKey, publicKey := GenerateEphemeralKeyPair()

	// Perform forward conversion
	em, err := ConvertConfidentialDataToEncryptedMessage(cm, publicKey)
	assert.Nil(t, err)

	emAtRest := em.ToBase64PEM()

	rbEm := EncryptedMessage{}
	rbErr := rbEm.FromBase64PEM(emAtRest)
	assert.Nil(t, rbErr)

	// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(privateKey, ciphertext, nil)
	}

	rvCm, rvErr := ConvertEncryptedMessageToConfidentialData(rbEm, decrypter)
	assert.Nil(t, rvErr)

	assert.Equal(t, cm.BinaryData, rvCm.BinaryData)
	assert.Equal(t, cm.StringData, rvCm.StringData)
	assert.Equal(t, cm.Labels, rvCm.Labels)
	assert.Equal(t, cm.Uuid, rvCm.Uuid)
	assert.Equal(t, cm.Type, rvCm.Type)
}

func Test_VersionDataToEncryptedMessageConversionWithAESWithBase64(t *testing.T) {

	buf := make([]byte, 10240)
	_, err := rand.Read(buf)
	assert.Nil(t, err)

	cm := CreateConfidentialBinaryData(buf, "example", nil)
	privateKey, publicKey := GenerateEphemeralKeyPair()

	// Perform forward conversion
	em, err := ConvertConfidentialDataToEncryptedMessage(cm, publicKey)
	assert.Nil(t, err)

	emAtRest := em.ToBase64PEM()

	rbEm := EncryptedMessage{}
	rbErr := rbEm.FromBase64PEM(emAtRest)
	assert.Nil(t, rbErr)

	// Perform backward conversion
	decrypter := func(ciphertext []byte) ([]byte, error) {
		return RsaDecryptBytes(privateKey, ciphertext, nil)
	}

	rvCm, rvErr := ConvertEncryptedMessageToConfidentialData(rbEm, decrypter)
	assert.Nil(t, rvErr)

	assert.Equal(t, cm.BinaryData, rvCm.BinaryData)
	assert.Equal(t, cm.StringData, rvCm.StringData)
	assert.Equal(t, cm.Labels, rvCm.Labels)
	assert.Equal(t, cm.Uuid, rvCm.Uuid)
	assert.Equal(t, cm.Type, rvCm.Type)
}

func Test_IsResourceNotFoundError(t *testing.T) {
	txt := "GET" +
		" https://lspwd2-d-confidential-kv.vault.azure.net/secrets/example-secret-3a/b3b6937782b840989d248ce90f71c709" +
		" --------------------------------------------------------------------------------\n" +
		"RESPONSE 404: 404 Not Found\n" +
		" ERROR CODE: SecretNotFound\n" +
		" --------------------------------------------------------------------------------\n│" +
		"{\n" +
		"   \"error\": {\n" +
		"     \"code\": \"SecretNotFound\",\n" +
		"     \"message\": \"A secret with (name/id) example-secret-3a/b3b6937782b840989d248ce90f71c709 was not found in this key vault. If you recently deleted this secret you may be able to recover it using the correct recovery command. For help resolving this issue, please see https://go.microsoft.com/fwlink/?linkid=2125182\"\n" +
		"   }\n" +
		" }\n" +
		" --------------------------------------------------------------------------------"

	assert.True(t, IsResourceNotFoundError(errors.New(txt)))
	assert.False(t, IsResourceNotFoundError(fmt.Errorf("is is not an expected message")))
}
