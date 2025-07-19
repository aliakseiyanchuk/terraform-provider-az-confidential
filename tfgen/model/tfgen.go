package model

import (
	"crypto/rsa"
)

type ContentWrappingParams struct {
	Labels           []string
	LoadRsaPublicKey func() (*rsa.PublicKey, error)

	WrappingKeyCoordinate WrappingKey
	AddTargetLabel        bool
}

func (kwp *ContentWrappingParams) AddLabel(label string) {
	kwp.Labels = append(kwp.Labels, label)
}

func (kwp *ContentWrappingParams) GetLabels() []string {
	return kwp.Labels
}
