package core

import "github.com/google/uuid"

type VersionedKeyVaultCertConfidentialDataJsonModel struct {
	BaseVersionedConfidentialDataJsonModel

	CertificateData         string `json:"crt"`
	CertificateDataFormat   string `json:"crt_f"`
	CertificateDataPassword string `json:"crt_p"`
}

func (vcd *VersionedKeyVaultCertConfidentialDataJsonModel) From(v VersionedKeyVaultCertificateData) {
	vcd.BaseVersionedConfidentialDataJsonModel.From(v)

	ConvertBytesToBase64(v.GetCertificateData, &vcd.CertificateData)
	vcd.CertificateDataFormat = v.GetCertificateDataFormat()
	vcd.CertificateDataPassword = v.GetCertificateDataPassword()
}

func (vcd *VersionedKeyVaultCertConfidentialDataJsonModel) Into(v SettableVersionedKeyVaultCertificateData) {
	vcd.BaseVersionedConfidentialDataJsonModel.Into(v)

	ConvertBase64ToBytes(&vcd.CertificateData, v.SetCertificateData)
	v.SetCertificateDataFormat(vcd.CertificateDataFormat)
	v.SetCertificateDataPassword(vcd.CertificateDataPassword)
}

type VersionedKeyVaultCertConfidentialDataStruct struct {
	BaseVersionedConfidentialDataStruct

	CertificateData         []byte
	CertificateDataFormat   string
	CertificateDataPassword string
}

func (v *VersionedKeyVaultCertConfidentialDataStruct) GetCertificateData() []byte {
	return v.CertificateData
}

func (v *VersionedKeyVaultCertConfidentialDataStruct) GetCertificateDataFormat() string {
	return v.CertificateDataFormat
}

func (v *VersionedKeyVaultCertConfidentialDataStruct) GetCertificateDataPassword() string {
	return v.CertificateDataPassword
}

func (v *VersionedKeyVaultCertConfidentialDataStruct) SetCertificateData(bytes []byte) {
	v.CertificateData = bytes
}

func (v *VersionedKeyVaultCertConfidentialDataStruct) SetCertificateDataFormat(s string) {
	v.CertificateDataFormat = s
}

func (v *VersionedKeyVaultCertConfidentialDataStruct) SetCertificateDataPassword(s string) {
	v.CertificateDataPassword = s
}

type VersionedKeyVaultCertificateDataHelper struct {
	VersionedConfidentialDataHelperTemplate[VersionedKeyVaultCertificateData, VersionedKeyVaultCertConfidentialDataJsonModel]
}

func (vcd *VersionedKeyVaultCertificateDataHelper) CreateConfidentialCertificateData(
	certData []byte, certFormat, certPassword, objType string, labels []string) VersionedKeyVaultCertificateData {
	rv := VersionedKeyVaultCertConfidentialDataStruct{
		BaseVersionedConfidentialDataStruct: BaseVersionedConfidentialDataStruct{
			Uuid:   uuid.New().String(),
			Type:   objType,
			Labels: labels,
		},
		CertificateData:         certData,
		CertificateDataFormat:   certFormat,
		CertificateDataPassword: certPassword,
	}

	vcd.KnowValue = &rv
	return vcd.KnowValue
}

func NewVersionedKeyVaultCertificateConfidentialDataHelper() *VersionedKeyVaultCertificateDataHelper {
	rv := &VersionedKeyVaultCertificateDataHelper{}
	rv.KnowValue = &VersionedKeyVaultCertConfidentialDataStruct{}
	rv.modelAtRestSupplier = func() VersionedKeyVaultCertConfidentialDataJsonModel {
		return VersionedKeyVaultCertConfidentialDataJsonModel{}
	}
	rv.valueToRest = func(data VersionedKeyVaultCertificateData) VersionedKeyVaultCertConfidentialDataJsonModel {
		rvMdl := VersionedKeyVaultCertConfidentialDataJsonModel{}
		rvMdl.From(data)
		return rvMdl
	}
	rv.restToValue = func(model VersionedKeyVaultCertConfidentialDataJsonModel) VersionedKeyVaultCertificateData {
		rvData := &VersionedKeyVaultCertConfidentialDataStruct{}
		model.Into(rvData)
		return rvData
	}

	return rv
}
