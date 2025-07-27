package core

import (
	"fmt"
	"github.com/segmentio/asm/base64"
)

type BinaryConfidentialDataJsonModel struct {
	BinaryData string `json:"b"`
}

func (vcd *BinaryConfidentialDataJsonModel) From(v ConfidentialBinaryData) {
	ConvertBytesToBase64(v.GetBinaryData, &vcd.BinaryData)
}

func (vcd *BinaryConfidentialDataJsonModel) Into(v SettableBinaryConfidentialData) {
	ConvertBase64ToBytes(&vcd.BinaryData, v.SetBinaryData)
}

// BinaryConfidentialDataStruct shows why runtime struct and model-at-rest exit.
// The data-at-rest is base-64 encoded, while at runtime these are bytes.
// Hence two data structures are required.
type BinaryConfidentialDataStruct struct {
	BinaryData []byte
}

func (v *BinaryConfidentialDataStruct) GetBinaryData() []byte {
	return v.BinaryData
}

func (v *BinaryConfidentialDataStruct) PayloadAsB64Ptr() *string {
	if len(v.GetBinaryData()) > 0 {
		rv := base64.StdEncoding.EncodeToString(v.GetBinaryData())
		return &rv
	} else {
		return nil
	}
}

func (v *BinaryConfidentialDataStruct) SetBinaryData(bytes []byte) {
	v.BinaryData = bytes
}

type VersionedBinaryConfidentialDataHelper struct {
	VersionedConfidentialDataHelperTemplate[ConfidentialBinaryData, BinaryConfidentialDataJsonModel]
}

func (vcd *VersionedBinaryConfidentialDataHelper) CreateConfidentialBinaryData(value []byte, md SecondaryProtectionParameters) VersionedConfidentialData[ConfidentialBinaryData] {
	p := VersionedConfidentialDataCreateParam[ConfidentialBinaryData]{
		SecondaryProtectionParameters: md,
		Value: &BinaryConfidentialDataStruct{
			BinaryData: value,
		},
	}

	return vcd.Set(p)
}

func NewVersionedBinaryConfidentialDataHelper(objectType string) *VersionedBinaryConfidentialDataHelper {
	rv := &VersionedBinaryConfidentialDataHelper{}
	rv.ModelName = "core/binary/v1"
	rv.ObjectType = objectType
	rv.KnowValue = &BinaryConfidentialDataStruct{}
	rv.ModelAtRestSupplier = func(modelRef string) (BinaryConfidentialDataJsonModel, error) {
		var err error
		if modelRef != "core/binary/v1" {
			err = fmt.Errorf("model reference %s is not correct", modelRef)
		}
		return BinaryConfidentialDataJsonModel{}, err
	}

	rv.ValueToRest = func(data ConfidentialBinaryData) BinaryConfidentialDataJsonModel {
		rvMdl := BinaryConfidentialDataJsonModel{}
		rvMdl.From(data)
		return rvMdl
	}
	rv.RestToValue = func(model BinaryConfidentialDataJsonModel) ConfidentialBinaryData {
		rvData := &BinaryConfidentialDataStruct{}
		model.Into(rvData)
		return rvData
	}

	return rv
}
