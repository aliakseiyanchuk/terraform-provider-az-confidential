package core

import "encoding/json"

type ConfidentialDataJsonHeader struct {
	Uuid           string   `json:"u"`
	Type           string   `json:"t"`
	Labels         []string `json:"l,omitempty"`
	ModelReference string   `json:"mrf,omitempty"`
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
