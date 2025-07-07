package core

// VersionedConfidentialData a base interface for an object carrying confidential data. Confidential data
// in this provider is associated with a unique UUID and set of labels. Subtypes will implement specific
// fields as required
type VersionedConfidentialData interface {
	GetUUID() string
	GetType() string
	GetLabels() []string
}

type SettableVersionedConfidentialData interface {
	SetUUID(v string)
	SetType(v string)
	SetLabels([]string)
}

type VersionedBinaryConfidentialData interface {
	VersionedConfidentialData
	GetBinaryData() []byte
	PayloadAsB64Ptr() *string
}

type SettableBinaryVersionedConfidentialData interface {
	SettableVersionedConfidentialData
	SetBinaryData([]byte)
}

type VersionedStringConfidentialData interface {
	VersionedConfidentialData
	GetStingData() string
}

type SettableVersionedStringConfidentialData interface {
	SettableVersionedConfidentialData
	SetStingData(string)
}

type VersionedKeyVaultCertificateData interface {
	VersionedConfidentialData
	GetCertificateData() []byte
	GetCertificateDataFormat() string
	GetCertificateDataPassword() string
}

type SettableVersionedKeyVaultCertificateData interface {
	SettableVersionedConfidentialData
	SetCertificateData([]byte)
	SetCertificateDataFormat(string)
	SetCertificateDataPassword(string)
}
