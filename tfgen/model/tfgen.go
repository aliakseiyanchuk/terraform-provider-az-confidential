package model

import (
	"crypto/rsa"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

type ContentWrappingParams struct {
	core.VersionedConfidentialMetadata

	LoadRsaPublicKey func() (*rsa.PublicKey, error)

	WrappingKeyCoordinate WrappingKey
	LockPlacement         bool
}

func (kwp *ContentWrappingParams) AddPlacementConstraints(label ...core.PlacementConstraint) {
	kwp.PlacementConstraints = append(kwp.PlacementConstraints, label...)
}

func (kwp *ContentWrappingParams) GetMetadataForTerraform(objName, destExp string) VersionedConfidentialMetadataTFCode {
	return VersionedConfidentialMetadataTFCode{
		VersionedConfidentialMetadata: kwp.VersionedConfidentialMetadata,
		ObjectSingular:                objName,
		DestinationArgument:           destExp,
	}
}
