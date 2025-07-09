package core

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
)

// VersionedConfidentialDataHelperTemplate a template class that aids constructing the versioned confidential
// data models. A serializable model carries two fields:
// - the confidential data itself which can be of any structure, and
// - a header describing the object type, object labels, and model reference.
type VersionedConfidentialDataHelperTemplate[T, TAtRest any] struct {
	KnowValue    T
	Header       ConfidentialDataJsonHeader
	ObjectType   string
	ObjectLabels []string
	ModelName    string

	modelAtRestSupplier MapperWithError[string, TAtRest]
	valueToRest         Mapper[T, TAtRest]
	restToValue         Mapper[TAtRest, T]
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Value() T {
	return vcd.KnowValue
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Set(t T, objectType string, labels []string) VersionedConfidentialData[T] {
	vcd.KnowValue = t
	vcd.ObjectType = objectType
	vcd.ObjectLabels = labels

	vcd.Header = ConfidentialDataJsonHeader{
		Uuid:           uuid.New().String(),
		Type:           vcd.ObjectType,
		Labels:         vcd.ObjectLabels,
		ModelReference: vcd.ModelName,
	}

	rv := VersionedConfidentialData[T]{
		Header: vcd.Header,
		Data:   vcd.KnowValue,
	}

	return rv
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Export() ([]byte, error) {
	modelAtRest := vcd.valueToRest(vcd.KnowValue)

	serializedObj := ConfidentialDataMarshalledJsonModel[TAtRest]{
		Header:           vcd.Header,
		ConfidentialData: modelAtRest,
	}

	jsonBytes, jsonErr := json.Marshal(serializedObj)
	if jsonErr != nil {
		return nil, jsonErr
	}

	return GZipCompress(jsonBytes), nil
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) ImportRaw(plainText []byte) (*VersionedConfidentialData[T], error) {
	rawMsg := ConfidentialDataMessageJson{}
	gunzip, gunzipErr := GZipDecompress(plainText)
	if gunzipErr != nil {
		return nil, gunzipErr
	}
	if jsonErr := json.Unmarshal(gunzip, &rawMsg); jsonErr != nil {
		return nil, jsonErr
	}

	if vcd.ModelName != rawMsg.Header.ModelReference {
		return nil, fmt.Errorf("unexpected model reference: this helper expected %s, but %s was received", vcd.ModelName, rawMsg.Header.ModelReference)
	}

	if rv, importErr := vcd.Import(rawMsg.ConfidentialData, rawMsg.Header.ModelReference); importErr != nil {
		return nil, importErr
	} else {
		vcd.Header = rawMsg.Header
		vcd.KnowValue = rv

		return &VersionedConfidentialData[T]{
			Header: rawMsg.Header,
			Data:   rv,
		}, nil
	}
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) ToEncryptedMessage(rsaKey *rsa.PublicKey) (EncryptedMessage, error) {
	rv := EncryptedMessage{}
	exportedBytes, exportErr := vcd.Export()
	if exportErr != nil {
		return rv, exportErr
	}

	encErr := rv.EncryptPlainText(exportedBytes, rsaKey)
	return rv, encErr
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Import(msg json.RawMessage, modelName string) (T, error) {
	jsonMdl, mdlErr := vcd.modelAtRestSupplier(modelName)
	if mdlErr != nil {
		return vcd.KnowValue, mdlErr
	}

	if jsonErr := json.Unmarshal(msg, &jsonMdl); jsonErr != nil {
		return vcd.KnowValue, jsonErr
	}

	vcd.KnowValue = vcd.restToValue(jsonMdl)
	return vcd.KnowValue, nil
}
