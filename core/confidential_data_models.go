package core

import "encoding/json"

type Stringifiable interface {
	String() string
}

func StringifiableComparator(a string, b Stringifiable) bool {
	return a == b.String()
}

type ProviderConstraint string
type PlacementConstraint string

func (p PlacementConstraint) String() string { return string(p) }
func (p ProviderConstraint) String() string  { return string(p) }

// ConfidentialDataJsonHeader is a header for the confidential material that provides the meta-information
// about what this confidential material is and the limits to its use
type ConfidentialDataJsonHeader struct {
	Uuid                 string                `json:"u"`
	Type                 string                `json:"t"`
	CreateLimit          int64                 `json:"clt,omitempty,omitzero"`
	Expiry               int64                 `json:"exp,omitempty,omitzero"`
	NumUses              int                   `json:"nu,omitempty,omitzero"`
	ProviderConstraints  []ProviderConstraint  `json:"prc,omitempty"`
	PlacementConstraints []PlacementConstraint `json:"plc,omitempty"`
	ModelReference       string                `json:"mrf,omitempty"`
}

type ConfidentialDataMessageJson struct {
	Header           ConfidentialDataJsonHeader `json:"header"`
	ConfidentialData json.RawMessage            `json:"data"`
}

// VersionedConfidentialData versioned confidential data; runtime counterpart
// of marshalled JSON model ConfidentialDataMarshalledJsonModel
type VersionedConfidentialData[K any] struct {
	Header ConfidentialDataJsonHeader
	Data   K
}

// ConfidentialDataMarshalledJsonModel is a helper generic struct that allows
// the actual producer to plug in any type of confidential data.
type ConfidentialDataMarshalledJsonModel[K any] struct {
	Header           ConfidentialDataJsonHeader `json:"header"`
	ConfidentialData K                          `json:"data"`
}
