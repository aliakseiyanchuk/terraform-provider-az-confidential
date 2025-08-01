package core

import (
	"crypto/rsa"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"strings"
	"time"
)

// SecondaryProtectionParameters secondary protection parameters (in addition to the access to the private key)
// that needs to be embedded in the ciphertext
type SecondaryProtectionParameters struct {
	ProviderConstraints  []ProviderConstraint
	PlacementConstraints []PlacementConstraint
	CreateLimit          int64
	Expiry               int64
	NumUses              int
}

func (p *SecondaryProtectionParameters) SameAs(other SecondaryProtectionParameters) bool {
	return p.NumUses == other.NumUses &&
		p.CreateLimit == other.CreateLimit &&
		p.Expiry == other.Expiry &&
		SameBag(func(a, b PlacementConstraint) bool { return a == b }, p.PlacementConstraints, other.PlacementConstraints) &&
		SameBag(func(a, b ProviderConstraint) bool { return a == b }, p.ProviderConstraints, other.ProviderConstraints)
}

func (p *SecondaryProtectionParameters) HasProviderConstraints() bool {
	return len(p.ProviderConstraints) > 0
}

func (p *SecondaryProtectionParameters) HasPlacementConstraints() bool {
	return len(p.PlacementConstraints) > 0
}

func (p *SecondaryProtectionParameters) LimitsCreate() bool {
	return p.CreateLimit > 0
}

func (p *SecondaryProtectionParameters) LimitsExpiry() bool {
	return p.Expiry > 0
}

func (p *SecondaryProtectionParameters) LimitsUsage() bool {
	return p.NumUses > 0
}

func (p *SecondaryProtectionParameters) IsUsedOnce() bool {
	return p.NumUses == 1
}

func (p *SecondaryProtectionParameters) GetCreateLimitTimestamp() string {
	return p.formatUnixTimestamp(p.CreateLimit)
}

func (p *SecondaryProtectionParameters) formatUnixTimestamp(limit int64) string {
	if limit > 0 {
		t := time.Unix(limit, 0)
		return FormatTime(&t).ValueString()
	} else {
		return "----PERPETUAL----"
	}
}

func (p *SecondaryProtectionParameters) GetExpiryTimestamp() string {
	return p.formatUnixTimestamp(p.Expiry)
}

func (p *SecondaryProtectionParameters) IsWeaklyProtected() bool {
	return !p.HasProviderConstraints() &&
		!p.HasPlacementConstraints() &&
		!p.LimitsExpiry() &&
		!p.LimitsCreate() &&
		!p.LimitsUsage()
}

type VersionedConfidentialDataCreateParam[T any] struct {
	SecondaryProtectionParameters
	Value T
}

// VersionedConfidentialDataHelperTemplate a template class that aids constructing the versioned confidential
// data models. A serializable model carries two fields:
// - the confidential data itself which can be of any structure, and
// - a header describing the object type, object labels, and model reference.
type VersionedConfidentialDataHelperTemplate[T, TAtRest any] struct {
	KnowValue  T
	Header     ConfidentialDataJsonHeader
	ObjectType string
	ModelName  string

	ModelAtRestSupplier MapperWithError[string, TAtRest]
	ValueToRest         Mapper[T, TAtRest]
	RestToValue         Mapper[TAtRest, T]
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Value() T {
	return vcd.KnowValue
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Set(p VersionedConfidentialDataCreateParam[T]) VersionedConfidentialData[T] {
	vcd.KnowValue = p.Value

	vcd.Header = ConfidentialDataJsonHeader{
		Uuid:                 uuid.New().String(),
		Type:                 vcd.ObjectType,
		CreateLimit:          p.CreateLimit,
		Expiry:               p.Expiry,
		ProviderConstraints:  p.ProviderConstraints,
		PlacementConstraints: p.PlacementConstraints,
		ModelReference:       vcd.ModelName,
		NumUses:              p.NumUses,
	}

	rv := VersionedConfidentialData[T]{
		Header: vcd.Header,
		Data:   vcd.KnowValue,
	}

	return rv
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Export() ([]byte, error) {
	modelAtRest := vcd.ValueToRest(vcd.KnowValue)

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

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) FromEncryptedMessage(em EncryptedMessage, decrypter RSADecrypter) error {
	plainText, decryptErr := em.ExtractPlainText(decrypter)
	if decryptErr != nil {
		return decryptErr
	}

	gzip, gzipErr := GZipDecompress(plainText)
	if gzipErr != nil {
		return gzipErr
	}

	v := ConfidentialDataMessageJson{}
	jsonErr := json.Unmarshal(gzip, &v)
	if jsonErr != nil {
		return jsonErr
	}

	if vcd.ObjectType != v.Header.Type {
		return fmt.Errorf("unexpected object type: expected %s, got %s", vcd.ObjectType, v.Header.Type)
	}

	vcd.Header = v.Header

	vcd.ModelName = v.Header.ModelReference

	specificValue, sErr := vcd.Import(v.ConfidentialData, v.Header.ModelReference)
	vcd.KnowValue = specificValue

	return sErr
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) ToEncryptedMessage(rsaKey *rsa.PublicKey) (EncryptedMessage, error) {
	rv := EncryptedMessage{
		headers: map[string]string{
			"CreateLimit": fmt.Sprintf("%d", vcd.Header.CreateLimit),
			"Expiry":      fmt.Sprintf("%d", vcd.Header.Expiry),
			"ProviderConstraints": strings.Join(
				MapSlice(
					func(constraint ProviderConstraint) string { return string(constraint) },
					vcd.Header.ProviderConstraints,
				),
				",",
			),
			"PlacementConstraints": strings.Join(
				MapSlice(
					func(constraint PlacementConstraint) string { return string(constraint) },
					vcd.Header.PlacementConstraints,
				),
				",",
			),
			"Type":           vcd.Header.Type,
			"ModelReference": vcd.Header.ModelReference,
		},
	}
	exportedBytes, exportErr := vcd.Export()
	if exportErr != nil {
		return rv, exportErr
	}

	encErr := rv.EncryptPlainText(exportedBytes, rsaKey)
	return rv, encErr
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) DefaultValue() T {
	// A convention is that a template will always have a model that never errs; so the default
	// value is available.
	t, _ := vcd.ModelAtRestSupplier(vcd.ModelName)
	return vcd.RestToValue(t)
}

func (vcd *VersionedConfidentialDataHelperTemplate[T, TAtRest]) Import(msg json.RawMessage, modelName string) (T, error) {
	jsonMdl, mdlErr := vcd.ModelAtRestSupplier(modelName)
	if mdlErr != nil {
		return vcd.KnowValue, mdlErr
	}

	if jsonErr := json.Unmarshal(msg, &jsonMdl); jsonErr != nil {
		return vcd.KnowValue, jsonErr
	}

	vcd.KnowValue = vcd.RestToValue(jsonMdl)
	return vcd.KnowValue, nil
}
