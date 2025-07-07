package core

import (
	"github.com/google/uuid"
)

// VersionedStringConfidentialDataJsonModel JSON model of the string confidential data
type VersionedStringConfidentialDataJsonModel struct {
	BaseVersionedConfidentialDataJsonModel

	StringData string `json:"s"`
}

func (vcd *VersionedStringConfidentialDataJsonModel) From(v VersionedStringConfidentialData) {
	vcd.BaseVersionedConfidentialDataJsonModel.From(v)
	vcd.StringData = v.GetStingData()
}

func (vcd *VersionedStringConfidentialDataJsonModel) Into(v SettableVersionedStringConfidentialData) {
	vcd.BaseVersionedConfidentialDataJsonModel.Into(v)
	v.SetStingData(vcd.StringData)
}

// VersionedStringConfidentialDataStruct is a confidential data comprising a single string
type VersionedStringConfidentialDataStruct struct {
	BaseVersionedConfidentialDataStruct

	StringData string
}

func (vcd *VersionedStringConfidentialDataStruct) GetStingData() string {
	return vcd.StringData
}

func (vcd *VersionedStringConfidentialDataStruct) SetStingData(s string) {
	vcd.StringData = s
}

func NewVersionedStringConfidentialDataHelper() *VersionedStringConfidentialDataHelper {
	rv := &VersionedStringConfidentialDataHelper{}
	rv.KnowValue = &VersionedStringConfidentialDataStruct{}

	rv.modelAtRestSupplier = func() VersionedStringConfidentialDataJsonModel { return VersionedStringConfidentialDataJsonModel{} }
	rv.valueToRest = func(data VersionedStringConfidentialData) VersionedStringConfidentialDataJsonModel {
		rvMdl := VersionedStringConfidentialDataJsonModel{}
		rvMdl.From(data)
		return rvMdl
	}
	rv.restToValue = func(model VersionedStringConfidentialDataJsonModel) VersionedStringConfidentialData {
		rvData := &VersionedStringConfidentialDataStruct{}
		model.Into(rvData)
		return rvData
	}

	return rv
}

type VersionedStringConfidentialDataHelper struct {
	VersionedConfidentialDataHelperTemplate[VersionedStringConfidentialData, VersionedStringConfidentialDataJsonModel]
}

func (vcd *VersionedStringConfidentialDataHelper) CreateConfidentialStringData(value, objType string, labels []string) VersionedStringConfidentialData {
	rv := VersionedStringConfidentialDataStruct{
		BaseVersionedConfidentialDataStruct: BaseVersionedConfidentialDataStruct{
			Uuid:   uuid.New().String(),
			Type:   objType,
			Labels: labels,
		},
		StringData: value,
	}

	vcd.KnowValue = &rv

	return vcd.KnowValue
}
