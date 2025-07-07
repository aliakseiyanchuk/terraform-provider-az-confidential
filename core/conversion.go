package core

import (
	"github.com/segmentio/asm/base64"
	"strings"
)

func ConvertBytesToBase64(from Supplier[[]byte], into *string) {
	b := from()
	if len(b) == 0 {
		*into = ""
	} else {
		*into = base64.StdEncoding.EncodeToString(b)
	}
}

func ConvertToPrt[T any](from Supplier[T]) *T {
	b := from()
	return &b
}

func ConvertBytesAsBase64StringPtr(from Supplier[[]byte]) *string {
	b := from()
	if len(b) == 0 {
		return nil
	} else {
		v := base64.StdEncoding.EncodeToString(b)
		return &v
	}
}

func ConvertBase64ToBytes(from *string, into Consumer[[]byte]) {
	if from == nil || len(*from) == 0 {
		into(nil)
	} else {
		val, _ := base64.StdEncoding.DecodeString(*from)
		into(val)
	}
}

// RSADecrypter function that will yield a plain-text for the ciphertext
type RSADecrypter func([]byte) ([]byte, error)

func IsResourceNotFoundError(err error) bool {
	return strings.Index(err.Error(), "RESPONSE 404: 404 Not Found") > 0
}
