package core

import (
	"fmt"
)

// StringConfidentialDataJsonModel JSON model of the string confidential data
type StringConfidentialDataJsonModel struct {
	StringData string `json:"s"`
}

func (vcd *StringConfidentialDataJsonModel) From(v ConfidentialStringData) {
	vcd.StringData = v.GetStingData()
}

func (vcd *StringConfidentialDataJsonModel) Into(v SettableStringConfidentialData) {
	v.SetStingData(vcd.StringData)
}

func (vcd *StringConfidentialDataJsonModel) GetStingData() string {
	return vcd.StringData
}

func (vcd *StringConfidentialDataJsonModel) SetStingData(s string) {
	vcd.StringData = s
}

func NewVersionedStringConfidentialDataHelper(objectType string) *VersionedStringConfidentialDataHelper {
	rv := &VersionedStringConfidentialDataHelper{}
	rv.KnowValue = &StringConfidentialDataJsonModel{}
	rv.ModelName = "core/string/v1"
	rv.ObjectType = objectType

	rv.ModelAtRestSupplier = func(modelName string) (StringConfidentialDataJsonModel, error) {
		if modelName != "core/string/v1" {
			return StringConfidentialDataJsonModel{}, fmt.Errorf("model name %s is not supported", modelName)
		}

		return StringConfidentialDataJsonModel{}, nil
	}

	rv.ValueToRest = func(data ConfidentialStringData) StringConfidentialDataJsonModel {
		rvMdl := StringConfidentialDataJsonModel{}
		rvMdl.From(data)
		return rvMdl
	}

	rv.RestToValue = func(model StringConfidentialDataJsonModel) ConfidentialStringData {
		rvData := &StringConfidentialDataJsonModel{}
		model.Into(rvData)
		return rvData
	}

	return rv
}

type VersionedStringConfidentialDataHelper struct {
	VersionedConfidentialDataHelperTemplate[ConfidentialStringData, StringConfidentialDataJsonModel]
}

func (vcd *VersionedStringConfidentialDataHelper) CreateConfidentialStringData(v string, md SecondaryProtectionParameters) VersionedConfidentialData[ConfidentialStringData] {
	p := VersionedConfidentialDataCreateParam[ConfidentialStringData]{
		SecondaryProtectionParameters: md,
		Value:                         &StringConfidentialDataJsonModel{StringData: v},
	}

	return vcd.Set(p)
}
