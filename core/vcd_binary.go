package core

import (
	"github.com/google/uuid"
	"github.com/segmentio/asm/base64"
)

type VersionedBinaryConfidentialDataJsonModel struct {
	BaseVersionedConfidentialDataJsonModel

	BinaryData string `json:"b"`
}

func (vcd *VersionedBinaryConfidentialDataJsonModel) From(v VersionedBinaryConfidentialData) {
	vcd.BaseVersionedConfidentialDataJsonModel.From(v)

	ConvertBytesToBase64(v.GetBinaryData, &vcd.BinaryData)
}

func (vcd *VersionedBinaryConfidentialDataJsonModel) Into(v SettableBinaryVersionedConfidentialData) {
	vcd.BaseVersionedConfidentialDataJsonModel.Into(v)

	ConvertBase64ToBytes(&vcd.BinaryData, v.SetBinaryData)
}

type VersionedBinaryConfidentialDataStruct struct {
	BaseVersionedConfidentialDataStruct

	BinaryData []byte
}

func (v *VersionedBinaryConfidentialDataStruct) GetBinaryData() []byte {
	return v.BinaryData
}

func (v *VersionedBinaryConfidentialDataStruct) PayloadAsB64Ptr() *string {
	if len(v.GetBinaryData()) > 0 {
		rv := base64.StdEncoding.EncodeToString(v.GetBinaryData())
		return &rv
	} else {
		return nil
	}
}

func (v *VersionedBinaryConfidentialDataStruct) SetBinaryData(bytes []byte) {
	v.BinaryData = bytes
}

type VersionedBinaryConfidentialDataHelper struct {
	VersionedConfidentialDataHelperTemplate[VersionedBinaryConfidentialData, VersionedBinaryConfidentialDataJsonModel]
}

func (vcd *VersionedBinaryConfidentialDataHelper) CreateConfidentialBinaryData(value []byte, objType string, labels []string) VersionedBinaryConfidentialData {
	rv := VersionedBinaryConfidentialDataStruct{
		BaseVersionedConfidentialDataStruct: BaseVersionedConfidentialDataStruct{
			Uuid:   uuid.New().String(),
			Type:   objType,
			Labels: labels,
		},
		BinaryData: value,
	}

	vcd.KnowValue = &rv

	return vcd.KnowValue
}

func NewVersionedBinaryConfidentialDataHelper() *VersionedBinaryConfidentialDataHelper {
	rv := &VersionedBinaryConfidentialDataHelper{}
	rv.KnowValue = &VersionedBinaryConfidentialDataStruct{}
	rv.modelAtRestSupplier = func() VersionedBinaryConfidentialDataJsonModel { return VersionedBinaryConfidentialDataJsonModel{} }
	rv.valueToRest = func(data VersionedBinaryConfidentialData) VersionedBinaryConfidentialDataJsonModel {
		rvMdl := VersionedBinaryConfidentialDataJsonModel{}
		rvMdl.From(data)
		return rvMdl
	}
	rv.restToValue = func(model VersionedBinaryConfidentialDataJsonModel) VersionedBinaryConfidentialData {
		rvData := &VersionedBinaryConfidentialDataStruct{}
		model.Into(rvData)
		return rvData
	}

	return rv
}
