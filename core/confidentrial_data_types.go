package core

type ConfidentialBinaryData interface {
	GetBinaryData() []byte
	PayloadAsB64Ptr() *string
}

type SettableBinaryConfidentialData interface {
	SetBinaryData([]byte)
}

type ConfidentialStringData interface {
	GetStingData() string
}

type SettableStringConfidentialData interface {
	SetStingData(string)
}

type ConfidentialCertificateData interface {
	GetCertificateData() []byte
	GetCertificateDataFormat() string
	GetCertificateDataPassword() string
}

type SettableConfidentialCertificateData interface {
	SetCertificateData([]byte)
	SetCertificateDataFormat(string)
	SetCertificateDataPassword(string)
}
