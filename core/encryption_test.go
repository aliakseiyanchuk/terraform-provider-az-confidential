package core

import (
	_ "embed"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"testing"
)
import _ "github.com/stretchr/testify/assert"

//go:embed ephemeral-rsa-public-key.pem
var ephemeralRsaKeyText []byte

func TestAESEncryption(t *testing.T) {
	plainText := []byte("this is a secret string")
	cipherText, aesData, err := AESEncrypt(plainText)

	assert.Nil(t, err)
	assert.NotEqual(t, plainText, cipherText)

	revDecrypt, revDecrError := AESDecrypt(cipherText, aesData)
	assert.Nil(t, revDecrError)
	assert.Equal(t, plainText, revDecrypt)
}

func TestGZipCompression(t *testing.T) {
	input := []byte("this is an input string string string string string string")
	gzippedStr := GZipCompress(input)
	assert.True(t, len(gzippedStr) < len(input))

	output, gzipErr := GZipDecompress(gzippedStr)
	assert.Nil(t, gzipErr)
	assert.Equal(t, input, output)
}

func TestLoadPublicKeySucceedsForRSAKey(t *testing.T) {
	rsaKey, err := LoadPublicKeyFromData(ephemeralRsaKeyText)
	assert.Nil(t, err)
	assert.NotNil(t, rsaKey)
}

func TestLoadPublicKeyFailsForUnexpectedKeys(t *testing.T) {
	rsaKey, err := LoadPublicKeyFromData([]byte("this is not a public key"))
	assert.NotNil(t, err)
	assert.Equal(t, "no RSA key found in the input", err.Error())
	assert.Nil(t, rsaKey)
}

func TestRSAEncrypt(t *testing.T) {
	_, aesData, aesErr := AESEncrypt([]byte("this is a secret string"))
	assert.Nil(t, aesErr)

	rsaKey, err := LoadPublicKeyFromData(ephemeralRsaKeyText)
	assert.Nil(t, err)
	assert.NotNil(t, rsaKey)

	rsaCiphertext, rsaErr := RsaEncrypt(aesData, rsaKey, []byte("this is a label"))
	assert.Nil(t, rsaErr)
	assert.NotNil(t, rsaCiphertext)
	assert.True(t, len(rsaCiphertext) == 512)
}

// This is "P-521" curve
//
//go:embed private-ec-key-secp521r1.pem
var secp256r1EcPrivateKey string

// THis is "P-384" curve
//
//go:embed private-ec-key-secp384r1.pem
var secp384r1EcPrivateKey string

// This is "P-256"
//
//go:embed private-ec-key-prime256v1.pem
var prime256v1EcPrivateKey string

// This is "P-256K" curve; however it isn't supported.
// DISABLED go:embed private-ec-key-secp256k1.pem
//var secp256k1EcPrivateKey string

//go:embed ephemeral-rsa-private-key.pem
var rsaPrivateKey string

func TestPrivateKeyToJWKConversion(t *testing.T) {
	keys := []string{
		secp256r1EcPrivateKey,
		secp384r1EcPrivateKey,
		prime256v1EcPrivateKey,
		//secp256k1EcPrivateKey,
	}

	for i, keyTxt := range keys {
		jwkOut := azkeys.JSONWebKey{}
		err := PrivateKeyTOJSONWebKey([]byte(keyTxt), &jwkOut)
		assert.Nilf(t, err, "Failed to convert key to JSONWebKey; key elem %d", i)

		assert.Equal(t, azkeys.KeyTypeEC, *jwkOut.Kty)
	}

	rsaJwkOut := azkeys.JSONWebKey{}
	rsaJwkErr := PrivateKeyTOJSONWebKey([]byte(rsaPrivateKey), &rsaJwkOut)
	assert.Nil(t, rsaJwkErr)
	assert.Equal(t, azkeys.KeyTypeRSA, *rsaJwkOut.Kty)
}
