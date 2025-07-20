package model

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestFoldString(t *testing.T) {
	str := "abcdefghij"
	arr := FoldString(str, 4)

	assert.Equal(t, 3, len(arr))
	assert.Equal(t, "abcd", arr[0])
	assert.Equal(t, "efgh", arr[1])
	assert.Equal(t, "ij", arr[2])
}

func TestEncryptedMessageWillBeReadFromFoldedString(t *testing.T) {
	rsaKey, err := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.Nil(t, err)

	em := core.EncryptedMessage{}
	encErr := em.EncryptPlainText([]byte("this is a secret message"), rsaKey)
	assert.Nil(t, encErr)

	pem := em.ToBase64PEM()
	foldedChunks := FoldString(pem, 4)
	foldedStr := strings.Join(foldedChunks, "\n  ")

	rbEm := core.EncryptedMessage{}
	rbErr := rbEm.FromBase64PEM(foldedStr)
	assert.Nil(t, rbErr)
}
