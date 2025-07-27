package core

import (
	"fmt"
)

type ConfidentialCertConfidentialDataJsonModel struct {
	CertificateData         string `json:"crt"`
	CertificateDataFormat   string `json:"crt_f"`
	CertificateDataPassword string `json:"crt_p"`
}

func (vcd *ConfidentialCertConfidentialDataJsonModel) From(v ConfidentialCertificateData) {
	ConvertBytesToBase64(v.GetCertificateData, &vcd.CertificateData)
	vcd.CertificateDataFormat = v.GetCertificateDataFormat()
	vcd.CertificateDataPassword = v.GetCertificateDataPassword()
}

func (vcd *ConfidentialCertConfidentialDataJsonModel) Into(v SettableConfidentialCertificateData) {
	ConvertBase64ToBytes(&vcd.CertificateData, v.SetCertificateData)
	v.SetCertificateDataFormat(vcd.CertificateDataFormat)
	v.SetCertificateDataPassword(vcd.CertificateDataPassword)
}

type ConfidentialCertConfidentialDataStruct struct {
	CertificateData         []byte
	CertificateDataFormat   string
	CertificateDataPassword string
}

func (v *ConfidentialCertConfidentialDataStruct) GetCertificateData() []byte {
	return v.CertificateData
}

func (v *ConfidentialCertConfidentialDataStruct) GetCertificateDataFormat() string {
	return v.CertificateDataFormat
}

func (v *ConfidentialCertConfidentialDataStruct) GetCertificateDataPassword() string {
	return v.CertificateDataPassword
}

func (v *ConfidentialCertConfidentialDataStruct) SetCertificateData(bytes []byte) {
	v.CertificateData = bytes
}

func (v *ConfidentialCertConfidentialDataStruct) SetCertificateDataFormat(s string) {
	v.CertificateDataFormat = s
}

func (v *ConfidentialCertConfidentialDataStruct) SetCertificateDataPassword(s string) {
	v.CertificateDataPassword = s
}

type VersionedKeyVaultCertificateDataHelper struct {
	VersionedConfidentialDataHelperTemplate[ConfidentialCertificateData, ConfidentialCertConfidentialDataJsonModel]
}

func (vcd *VersionedKeyVaultCertificateDataHelper) CreateConfidentialCertificateData(
	certData []byte, certFormat, certPassword string, md SecondaryProtectionParameters) VersionedConfidentialData[ConfidentialCertificateData] {

	confData := &ConfidentialCertConfidentialDataStruct{
		CertificateData:         certData,
		CertificateDataFormat:   certFormat,
		CertificateDataPassword: certPassword,
	}

	return vcd.FromConfidentialCertificateData(confData, md)
}

func (vcd *VersionedKeyVaultCertificateDataHelper) FromConfidentialCertificateData(
	confData ConfidentialCertificateData, md SecondaryProtectionParameters) VersionedConfidentialData[ConfidentialCertificateData] {

	p := VersionedConfidentialDataCreateParam[ConfidentialCertificateData]{
		SecondaryProtectionParameters: md,
		Value:                         confData,
	}

	return vcd.Set(p)
}

func NewVersionedKeyVaultCertificateConfidentialDataHelper(objectType string) *VersionedKeyVaultCertificateDataHelper {
	rv := &VersionedKeyVaultCertificateDataHelper{}
	rv.KnowValue = &ConfidentialCertConfidentialDataStruct{}
	rv.ModelName = "core/certificate/v01"
	rv.ObjectType = objectType

	rv.ModelAtRestSupplier = func(modelName string) (ConfidentialCertConfidentialDataJsonModel, error) {
		var err error
		if modelName != "core/certificate/v01" {
			err = fmt.Errorf("unknown model name %s", modelName)
		}

		return ConfidentialCertConfidentialDataJsonModel{}, err
	}
	rv.ValueToRest = func(data ConfidentialCertificateData) ConfidentialCertConfidentialDataJsonModel {
		rvMdl := ConfidentialCertConfidentialDataJsonModel{}
		rvMdl.From(data)
		return rvMdl
	}
	rv.RestToValue = func(model ConfidentialCertConfidentialDataJsonModel) ConfidentialCertificateData {
		rvData := &ConfidentialCertConfidentialDataStruct{}
		model.Into(rvData)
		return rvData
	}

	return rv
}
