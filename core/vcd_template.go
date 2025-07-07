package core

import (
	"crypto/rsa"
	"encoding/json"
)

type VersionedConfidentialDataHelperTemplate[T VersionedConfidentialData, TAtRest any] struct {
	KnowValue T

	modelAtRestSupplier Supplier[TAtRest]
	valueToRest         Mapper[T, TAtRest]
	restToValue         Mapper[TAtRest, T]
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Value() T {
	return vcd.KnowValue
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Export() ([]byte, error) {
	modelAtRest := vcd.valueToRest(vcd.KnowValue)
	jsonBytes, jsonErr := json.Marshal(modelAtRest)
	if jsonErr != nil {
		return nil, jsonErr
	}

	return GZipCompress(jsonBytes), nil
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) ToEncryptedMessage(rsaKey *rsa.PublicKey) (EncryptedMessage, error) {
	rv := EncryptedMessage{}
	expotedBytes, exportErr := vcd.Export()
	if exportErr != nil {
		return rv, exportErr
	}

	encErr := rv.EncryptPlainText(expotedBytes, rsaKey)
	return rv, encErr
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Import(data []byte) (T, error) {
	gunzip, gunzipErr := GZipDecompress(data)
	if gunzipErr != nil {
		return vcd.KnowValue, gunzipErr
	}

	jsonMdl := vcd.modelAtRestSupplier()
	if jsonErr := json.Unmarshal(gunzip, &jsonMdl); jsonErr != nil {
		return vcd.KnowValue, jsonErr
	}

	vcd.KnowValue = vcd.restToValue(jsonMdl)
	return vcd.KnowValue, nil
}
