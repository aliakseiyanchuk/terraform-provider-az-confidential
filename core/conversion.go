package core

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/segmentio/asm/base64"
	"strings"
)

func CreateConfidentialStringData(value, objType string, labels []string) VersionedConfidentialData {
	rv := VersionedConfidentialData{
		Uuid:       uuid.New().String(),
		Type:       objType,
		StringData: value,
		Labels:     labels,
	}

	return rv
}

func CreateConfidentialBinaryData(value []byte, objType string, labels []string) VersionedConfidentialData {
	rv := VersionedConfidentialData{
		Uuid:       uuid.New().String(),
		Type:       objType,
		BinaryData: value,
		Labels:     labels,
	}

	return rv
}

func CreateDualConfidentialData(value []byte, strValue string, objType string, labels []string) VersionedConfidentialData {
	rv := VersionedConfidentialData{
		Uuid:       uuid.New().String(),
		Type:       objType,
		BinaryData: value,
		StringData: strValue,
		Labels:     labels,
	}

	return rv
}

type VersionedConfidentialDataJSONModel struct {
	Uuid          string   `json:"u"`
	Type          string   `json:"t"`
	BinaryPayload string   `json:"b,omitempty"`
	StringPayload string   `json:"s,omitempty"`
	Labels        []string `json:"l,omitempty"`
}

func (mdl *VersionedConfidentialDataJSONModel) AsJson() []byte {
	rv, _ := json.Marshal(mdl)
	return rv
}

func (mdl *VersionedConfidentialDataJSONModel) From(data VersionedConfidentialData) {
	mdl.Uuid = data.Uuid
	mdl.Type = data.Type

	if len(data.BinaryData) > 0 {
		mdl.BinaryPayload = base64.StdEncoding.EncodeToString(data.BinaryData)
	}

	mdl.StringPayload = data.StringData
	mdl.Labels = data.Labels
}

func (mdl *VersionedConfidentialDataJSONModel) Export() (VersionedConfidentialData, error) {
	rv := VersionedConfidentialData{}

	rv.Uuid = mdl.Uuid
	rv.Type = mdl.Type
	rv.StringData = mdl.StringPayload
	rv.Labels = mdl.Labels

	if len(mdl.BinaryPayload) > 0 {
		n, err := base64.StdEncoding.DecodeString(mdl.BinaryPayload)
		if err != nil {
			return rv, err
		}
		rv.BinaryData = n
	}

	return rv, nil
}

func ConvertConfidentialDataToEncryptedMessage(cm VersionedConfidentialData, rsaKey *rsa.PublicKey) (EncryptedMessage, error) {
	jsonModel := VersionedConfidentialDataJSONModel{}
	jsonModel.From(cm)

	jsonBytes := jsonModel.AsJson()
	gzippedBytes := GZipCompress(jsonBytes)

	return CreateEncryptedMessage(rsaKey, gzippedBytes)
}

// RSADecrypter function that will yield a plain-text for the ciphertext
type RSADecrypter func([]byte) ([]byte, error)

func ConvertEncryptedMessageToConfidentialData(em EncryptedMessage, decrypter RSADecrypter) (VersionedConfidentialData, error) {
	rv := VersionedConfidentialData{}
	var plaintext []byte

	if em.HasContentEncryptionKey() {
		cek, rsaErr := decrypter(em.contentEncryptionKey)
		if rsaErr != nil {
			return rv, fmt.Errorf("cannot decrypt CEK: %s", rsaErr.Error())
		}

		aesData := AESData{}
		if aesErr := aesData.FromBytes(cek); aesErr != nil {
			return rv, fmt.Errorf("cannot unmarshal AES key: %s", aesErr.Error())
		}

		if pt, decrErr := AESDecrypt(em.secretText, aesData); decrErr != nil {
			return rv, fmt.Errorf("cannot decrypt AES text: %s", decrErr.Error())
		} else {
			plaintext = pt
		}
	} else {
		if pt, rsaErr := decrypter(em.secretText); rsaErr != nil {
			return rv, fmt.Errorf("cannot decrypt plain text using RSA: %s", rsaErr.Error())
		} else {
			plaintext = pt
		}
	}

	jsonStr, gzipErr := GZipDecompress(plaintext)
	if gzipErr != nil {
		return rv, gzipErr
	}

	mdl := VersionedConfidentialDataJSONModel{}

	if err := json.Unmarshal(jsonStr, &mdl); err != nil {
		return rv, err
	}

	return mdl.Export()
}

func IsResourceNotFoundError(err error) bool {
	return strings.Index(err.Error(), "RESPONSE 404: 404 Not Found") > 0
}
