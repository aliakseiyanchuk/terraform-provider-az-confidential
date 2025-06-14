package core

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"testing"
)
import _ "github.com/stretchr/testify/assert"

//go:embed ephemeral-rsa-public-key.pem
var ephemeralRsaPublicKey []byte

//go:embed ephemeral-rsa-private-key.pem
var ephemeralRsaKeyText []byte

//go:embed ephemeral-rsa-private-key.der
var ephemeralRsaKeyDERForm []byte

//go:embed ephemeral-rsa-private-key-encrypted.pem
var ephemeralEncryptedRsaKeyText []byte

//go:embed ephemeral-rsa-private-key-encrypted.der
var ephemeralEncryptedRsaKeyDERForm []byte

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
	rsaKey, err := LoadPublicKeyFromData(ephemeralRsaPublicKey)
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

	rsaKey, err := LoadPublicKeyFromData(ephemeralRsaPublicKey)
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
		err := PrivateKeyTOJSONWebKey([]byte(keyTxt), "", &jwkOut)
		assert.Nilf(t, err, "Failed to convert key to JSONWebKey; key elem %d", i)

		assert.Equal(t, azkeys.KeyTypeEC, *jwkOut.Kty)
	}

	rsaJwkOut := azkeys.JSONWebKey{}
	rsaJwkErr := PrivateKeyTOJSONWebKey([]byte(rsaPrivateKey), "", &rsaJwkOut)
	assert.Nil(t, rsaJwkErr)
	assert.Equal(t, azkeys.KeyTypeRSA, *rsaJwkOut.Kty)
}

func BenchmarkOldStyle(b *testing.B) {
	// let's assume I'll do the init
	b.ResetTimer() // if setup may be expensive
	for range b.N {
		outKey := azkeys.JSONWebKey{}
		inbytes := []byte(rsaPrivateKey)
		err := PrivateKeyTOJSONWebKey(inbytes, "", &outKey)
		assert.Nil(b, err)
	}
	b.StopTimer()
	// And here we'll need to d the tear-down
}

func BenchmarkRSAKeyConversion(b *testing.B) {
	for b.Loop() {
		outKey := azkeys.JSONWebKey{}
		inbytes := []byte(rsaPrivateKey)
		err := PrivateKeyTOJSONWebKey(inbytes, "", &outKey)
		assert.Nil(b, err)
	}
}

func BenchmarkECKeyConversion(b *testing.B) {
	for b.Loop() {
		outKey := azkeys.JSONWebKey{}
		inbytes := []byte(prime256v1EcPrivateKey)
		err := PrivateKeyTOJSONWebKey(inbytes, "", &outKey)
		assert.Nil(b, err)
	}
}

type CrazyZeroType int

func (z CrazyZeroType) IsZero() bool {
	return int(z) < 100
}

type CrazyZeroStruct struct {
	Message string        `json:"message"`
	Number  CrazyZeroType `json:"number,omitempty,omitzero"`
}

func TestCrazyZero(t *testing.T) {
	v := &CrazyZeroStruct{
		Message: "this is a message",
		Number:  CrazyZeroType(50),
	}
	jsTxt, err := json.Marshal(v)
	assert.Nil(t, err)
	fmt.Println(string(jsTxt))
}

//go:embed ephemeral-certificate.pem
var ephemeralCertificatePEM []byte

//go:embed cert.pkcs12
var ephemeralCertPFX12 []byte

func TestIsPEMEncoded(t *testing.T) {
	assert.True(t, IsPEMEncoded(ephemeralRsaKeyText))
	assert.True(t, IsPEMEncoded(ephemeralCertificatePEM))

	assert.False(t, IsPEMEncoded(ephemeralCertPFX12))
}

func TestBlockExtraction(t *testing.T) {
	blocks, err := ParsePEMBlocks(ephemeralCertificatePEM)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(blocks))
	assert.Equal(t, "PRIVATE KEY", blocks[0].Type)
	assert.Equal(t, "CERTIFICATE", blocks[1].Type)

	blocks, err = ParsePEMBlocks(ephemeralCertPFX12)
	assert.Equal(t, 0, len(blocks))
	assert.NotNil(t, err)
}

func TestBytesToPrivateKey(t *testing.T) {
	block, blockErr := ParseSinglePEMBlock(ephemeralRsaKeyText)
	assert.Nil(t, blockErr)
	assert.False(t, RequiresPassword(block))

	key, err := PrivateKeyFromBlock(block)
	assert.Nil(t, err)
	assert.NotNil(t, key)
}

func TestBytesToPrivateKeyWithPassword(t *testing.T) {
	block, blockErr := ParseSinglePEMBlock(ephemeralEncryptedRsaKeyText)
	assert.Nil(t, blockErr)
	assert.True(t, RequiresPassword(block))

	key, err := PrivateKeyFromEncryptedBlock(block, "s1cr3t")
	assert.Nil(t, err)
	assert.NotNil(t, key)
}

func TestPrivateKeyToJSONWebKey(t *testing.T) {
	rsaOutJWK := azkeys.JSONWebKey{}
	rsaErr := PrivateKeyTOJSONWebKey(ephemeralRsaKeyText, "", &rsaOutJWK)
	assert.Nil(t, rsaErr)

	rsaOutDERJWK := azkeys.JSONWebKey{}
	rsaErr = PrivateKeyTOJSONWebKey(ephemeralRsaKeyDERForm, "", &rsaOutDERJWK)
	assert.Nil(t, rsaErr)

	rsaEncJWK := azkeys.JSONWebKey{}
	rsaErr = PrivateKeyTOJSONWebKey(ephemeralEncryptedRsaKeyText, "s1cr3t", &rsaEncJWK)
	assert.Nil(t, rsaErr)

	rsaEncDERJWK := azkeys.JSONWebKey{}
	rsaErr = PrivateKeyTOJSONWebKey(ephemeralEncryptedRsaKeyDERForm, "s1cr3t", &rsaEncDERJWK)
	assert.Nil(t, rsaErr)
}

//go:embed cert.pkcs12
var pkcs12File []byte

//func TestPKCS12Import(t *testing.T) {
//	_, _, pwdErr := pkcs12.Decode(pkcs12File, "s1cr3t")
//	assert.Nil(t, pwdErr)
//}
