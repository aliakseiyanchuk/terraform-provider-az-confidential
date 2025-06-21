package core

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"io"
	"os"
	"strings"

	"github.com/youmark/pkcs8"
)

type AESData struct {
	IV  []byte `json:"iv"`
	Key []byte `json:"key"`
	AAD []byte `json:"aad"`
}

func (a *AESData) ToBytes() []byte {
	jsonText, _ := json.Marshal(a)
	jsonGzip := GZipCompress(jsonText)

	return jsonGzip
}

func (a *AESData) FromBytes(input []byte) error {
	gunzip, gunzipErr := GZipDecompress(input)
	if gunzipErr != nil {
		return gunzipErr
	}

	if jsonErr := json.Unmarshal(gunzip, a); jsonErr != nil {
		return jsonErr
	}

	return nil
}

func Sha256Of(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

type EncryptedMessage struct {
	secretText           []byte
	contentEncryptionKey []byte
}

func (em *EncryptedMessage) GetContentEncryptionKeyExpr() string {
	if len(em.contentEncryptionKey) == 0 {
		return ""
	} else {
		return base64.StdEncoding.EncodeToString(em.contentEncryptionKey)
	}
}

func (em *EncryptedMessage) GetSecretExpr() string {
	if len(em.secretText) == 0 {
		return ""
	} else {
		return base64.StdEncoding.EncodeToString(em.secretText)
	}
}

func (em *EncryptedMessage) HasContentEncryptionKey() bool {
	return len(em.contentEncryptionKey) > 0
}

func (em *EncryptedMessage) ToPEM() []byte {
	if len(em.secretText) == 0 {
		return nil
	}

	textBlock := pem.Block{
		Type:    "CONTENT",
		Headers: map[string]string{},
		Bytes:   em.secretText,
	}

	output := bytes.Buffer{}
	writer := bufio.NewWriter(&output)

	pemErr := pem.Encode(writer, &textBlock)
	if pemErr != nil {
		fmt.Println(pemErr.Error())
	}
	if len(em.contentEncryptionKey) > 0 {
		cekBlock := pem.Block{
			Type:    "CEK",
			Bytes:   em.contentEncryptionKey,
			Headers: map[string]string{},
		}
		_ = pem.Encode(writer, &cekBlock)
	}

	_ = writer.Flush()
	return output.Bytes()
}

func (em *EncryptedMessage) ToBase64PEM() string {
	return base64.StdEncoding.EncodeToString(GZipCompress(em.ToPEM()))
}

func (em *EncryptedMessage) FromBase64PEM(v string) error {
	gzipped, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return fmt.Errorf("input must be a valid Base-64 encoded string; this error occured: %s", err.Error())
	}

	pemBytes, gzipErr := GZipDecompress(gzipped)
	if gzipErr != nil {
		return fmt.Errorf("input must include gzip compression; this error occured: %s", gzipErr.Error())
	}

	return em.FromPEM(pemBytes)
}

func (em *EncryptedMessage) FromPEM(data []byte) error {
	pemBloks, err := ParsePEMBlocks(data)
	if err != nil {
		return fmt.Errorf("cannot parse provided PEM input: %v", err)
	}

	if secretBlock := FindPEMBlock(pemBloks, "CONTENT"); secretBlock != nil {
		em.secretText = secretBlock.Bytes
	} else {
		return errors.New("provided input must contain at least CONTENT block")
	}

	if cekBlock := FindPEMBlock(pemBloks, "CEK"); cekBlock != nil {
		em.contentEncryptionKey = cekBlock.Bytes
	}

	return nil
}

var sha256HashSize = sha256.New().Size()

func CreateEncryptedMessage(rsaKey *rsa.PublicKey, payload []byte) (EncryptedMessage, error) {
	rv := EncryptedMessage{}

	// If the message is too long to be just encrypted with the RSA, we need to
	// habe a two-step scheme
	if len(payload) > rsaKey.Size()-2*sha256HashSize-2 {
		// First step: create AES encryption key and wrap the payload with it.
		encryptedPayload, aesData, encryptionErr := AESEncrypt(payload)
		if encryptionErr != nil {
			return rv, encryptionErr
		}
		rv.secretText = encryptedPayload

		encryptedCEK, cekEncryptionErr := RsaEncryptBytes(rsaKey, aesData.ToBytes(), nil)
		if cekEncryptionErr != nil {
			return rv, cekEncryptionErr
		}

		rv.contentEncryptionKey = encryptedCEK
		return rv, nil
	} else {
		encryptedPayload, encryptionErr := RsaEncryptBytes(rsaKey, payload, nil)
		if encryptionErr != nil {
			return rv, encryptionErr
		}

		rv.contentEncryptionKey = nil
		rv.secretText = encryptedPayload
		return rv, nil
	}
}

const aesKeySizeBits = 256

func AESDecrypt(ciphertext []byte, data AESData) ([]byte, error) {
	block, blockErr := aes.NewCipher(data.Key)
	if blockErr != nil {
		return nil, blockErr
	}

	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, gcmErr
	}

	return gcm.Open(nil, data.IV, ciphertext, data.AAD)
}

func AESEncrypt(plaintext []byte) ([]byte, AESData, error) {
	rv := AESData{
		Key: make([]byte, aesKeySizeBits/8),
	}

	if _, err := rand.Reader.Read(rv.Key); err != nil {
		return nil, rv, err
	}

	block, blockErr := aes.NewCipher(rv.Key)
	if blockErr != nil {
		return nil, rv, blockErr
	}

	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, rv, gcmErr
	}

	// Initialization vector is best randomly generated. It's
	// not a part of ciphertext and can be exchanged.
	rv.IV = make([]byte, gcm.NonceSize())
	if _, err := rand.Reader.Read(rv.IV); err != nil {
		return nil, rv, err
	}

	// Additional authentication data; e.g., reference an object
	// to detect unintended copying.
	rv.AAD = make([]byte, gcm.NonceSize())
	if _, err := rand.Reader.Read(rv.AAD); err != nil {
		return nil, rv, err
	}

	output := gcm.Seal(nil, rv.IV, plaintext, rv.AAD)
	return output, rv, nil
}

func RsaEncryptBytes(key *rsa.PublicKey, plaintext []byte, label []byte) ([]byte, error) {
	hash := sha256.New()
	ciphertext, _ := rsa.EncryptOAEP(hash, rand.Reader, key, plaintext, label)

	return ciphertext, nil
}

func RsaDecryptBytes(key *rsa.PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, key, ciphertext, label)
}

func GZipCompress(data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()

	return buf.Bytes()
}

func GZipDecompress(data []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	var outBuf bytes.Buffer
	bufWriter := bufio.NewWriter(&outBuf)

	_, err = io.Copy(bufWriter, gzipReader)
	_ = gzipReader.Close()

	if err != nil {
		return nil, err
	}

	return outBuf.Bytes(), nil
}

func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	pubText, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return LoadPublicKeyFromData(pubText)
}

func LoadPublicKeyFromData(pubText []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubText)
	if block == nil {
		return nil, errors.New("no RSA key found in the input")
	}

	switch block.Type {
	case "PUBLIC KEY":
		rsaPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		// The type needs to be asserted.
		return rsaPubKey.(*rsa.PublicKey), nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

func SymmetricKeyTOJSONWebKey(input []byte, outKey *azkeys.JSONWebKey) error {
	jwkKey, jwkErr := jwk.Import(input)
	if jwkErr != nil {
		return jwkErr
	}

	if octKey, ok := jwkKey.(jwk.SymmetricKey); ok {
		kty := azkeys.KeyTypeOct
		outKey.Kty = &kty

		port(&outKey.K, octKey.Octets)
		return nil
	} else {
		return errors.New("bytes did not procedure a symmetric key")
	}
}

func PrivateKeyTOJSONWebKey(input []byte, password string, outKey *azkeys.JSONWebKey) error {
	var key any
	var keyLoadErr error

	if IsPEMEncoded(input) {
		block, blockErr := ParseSinglePEMBlock(input)
		if blockErr != nil {
			return blockErr
		}
		if RequiresPassword(block) {
			key, keyLoadErr = PrivateKeyFromEncryptedBlock(block, password)
		} else {
			key, keyLoadErr = PrivateKeyFromBlock(block)
		}
	} else {
		// The private key is a DER-encoded private key.
		if len(password) == 0 {
			key, keyLoadErr = x509.ParsePKCS8PrivateKey(input)
		} else {
			key, keyLoadErr = PrivateKeyFromDER(input, password)
		}
	}

	if keyLoadErr != nil {
		return keyLoadErr
	}

	jwkKey, jwkErr := jwk.Import(key)
	if jwkErr != nil {
		return jwkErr
	}

	if rsaKey, ok := jwkKey.(jwk.RSAPrivateKey); ok {
		kty := azkeys.KeyTypeRSA

		outKey.Kty = &kty
		port(&outKey.D, rsaKey.D)
		port(&outKey.DP, rsaKey.DP)
		port(&outKey.DQ, rsaKey.DQ)
		port(&outKey.E, rsaKey.E)
		port(&outKey.N, rsaKey.N)
		port(&outKey.P, rsaKey.P)
		port(&outKey.Q, rsaKey.Q)
		port(&outKey.QI, rsaKey.QI)
	} else if ecKey, ok := jwkKey.(jwk.ECDSAPrivateKey); ok {
		kty := azkeys.KeyTypeEC
		outKey.Kty = &kty

		curveAlg, _ := ecKey.Crv()
		if azCurveAlg, notSupportedErr := azCurveFor(curveAlg); notSupportedErr != nil {
			return notSupportedErr
		} else {
			outKey.Crv = &azCurveAlg
		}

		port(&outKey.D, ecKey.D)
		port(&outKey.X, ecKey.X)
		port(&outKey.Y, ecKey.Y)
	} else {
		return errors.New("unsupported key type")
	}

	return nil
}

func azCurveFor(algorithm jwa.EllipticCurveAlgorithm) (azkeys.CurveName, error) {
	curvAlgName := algorithm.String()

	for _, cn := range azkeys.PossibleCurveNameValues() {
		if curvAlgName == string(cn) {
			return cn, nil
		}
	}

	return "UNKNOWN", errors.New(fmt.Sprintf("Curve algorithm %s is not supported by Azure", curvAlgName))
}

func port(target *[]byte, supplier func() ([]byte, bool)) {
	if data, exists := supplier(); exists {
		*target = data
	}
}

func RequiresPassword(block *pem.Block) bool {
	if block != nil {
		return block.Type == "ENCRYPTED PRIVATE KEY"
	}

	return false
}

func PrivateKeyFromDER(data []byte, password string) (any, error) {
	return pkcs8.ParsePKCS8PrivateKey(data, []byte(password))
}

// PrivateKeyFromBlock converts arbitrary bytes to a private key
func PrivateKeyFromBlock(block *pem.Block) (any, error) {
	b := block.Bytes

	if block.Type == "EC PRIVATE KEY" {
		key, err := x509.ParseECPrivateKey(b)
		return key, err
	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(b)
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			rsaKey.Precompute()
			if rsaKeyValidErr := rsaKey.Validate(); rsaKeyValidErr != nil {
				return nil, rsaKeyValidErr
			}
		}
		return key, err
	} else {
		return nil, fmt.Errorf("unsupported block type %q", block.Type)
	}
}

// PrivateKeyFromEncryptedBlock converts encrypted private key block to an RSA key
func PrivateKeyFromEncryptedBlock(block *pem.Block, password string) (any, error) {
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if decryptedKey, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password)); err != nil {
			return nil, err
		} else {
			return decryptedKey, nil
		}
	} else {
		return nil, fmt.Errorf("unsupported encrypted block type %q", block.Type)
	}
}

// IsPEMEncoded returns true if teh data source represents a valid PEM-encoded
// stream, comprising valid blocks.
func IsPEMEncoded(data []byte) bool {
	// Ensure that PEM blocks are well-formed.
	remainder := data
	var block *pem.Block

	for len(remainder) > 0 {
		block, remainder = pem.Decode(remainder)
		if block == nil {
			return false
		}
	}

	return true
}

func ParseSinglePEMBlock(data []byte) (*pem.Block, error) {
	if blocks, pemErr := ParsePEMBlocks(data); pemErr != nil {
		return nil, pemErr
	} else if len(blocks) != 1 {
		return nil, fmt.Errorf("input must contain exactly 1 block, but %d where found", len(blocks))
	} else {
		return blocks[0], nil
	}
}

func ParsePEMBlocks(data []byte) ([]*pem.Block, error) {
	remainder := data
	var rv []*pem.Block

	for len(remainder) > 0 {
		var block *pem.Block
		block, remainder = pem.Decode(remainder)
		if block == nil {
			return rv, errors.New(fmt.Sprintf("cannot read block #{%d} in this chaiun", len(rv)+1))
		} else {
			rv = append(rv, block)
		}
	}

	if len(rv) == 0 {
		return rv, errors.New("no PEM blocks found")
	}

	return rv, nil
}

func FindPrivateKeyBlock(blocks []*pem.Block) *pem.Block {
	if len(blocks) == 0 {
		return nil
	}

	for _, block := range blocks {
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return block
		}
	}

	return nil
}

func FindPEMBlock(blocks []*pem.Block, blockType string) *pem.Block {
	if len(blocks) == 0 {
		return nil
	}

	for _, block := range blocks {
		if block.Type == blockType {
			return block
		}
	}

	return nil
}

func FindCertificateBlocks(blocks []*pem.Block) []*pem.Block {
	if len(blocks) == 0 {
		return nil
	}

	var rv []*pem.Block

	for _, block := range blocks {
		if block.Type == "CERTIFICATE" {
			rv = append(rv, block)
		}
	}

	return rv
}

// GenerateEphemeralKeyPair generates the ephemeral key pari to be used for testing purposes, e.g. where
// actual decryption/encryption needs to be exercised.
func GenerateEphemeralKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	// Generate RSA key.
	bitSize := 4096
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	// Extract public component.
	pub := key.Public()
	rsaPubPrt := pub.(*rsa.PublicKey)

	return key, rsaPubPrt
}
