package model

import (
	"crypto/rsa"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

type ContentWrappingParams struct {
	core.SecondaryProtectionParameters

	LoadRsaPublicKey func() (*rsa.PublicKey, error)

	WrappingKeyCoordinate WrappingKey
	LockPlacement         bool
}

func (kwp *ContentWrappingParams) GetMetadataForTerraform(objName, destExp string) VersionedConfidentialMetadataTFCode {
	return kwp.GetMetadataForTerraformFor(kwp.SecondaryProtectionParameters, objName, destExp)
}

func (kwp *ContentWrappingParams) GetMetadataForTerraformFor(sp core.SecondaryProtectionParameters, objName, destExp string) VersionedConfidentialMetadataTFCode {
	return VersionedConfidentialMetadataTFCode{
		SecondaryProtectionParameters: sp,
		ObjectSingular:                objName,
		DestinationArgument:           destExp,
	}
}
