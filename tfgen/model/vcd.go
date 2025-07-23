package model

import (
	_ "embed"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

//go:embed metadata_description.tmpl
var confidentialDataAppraisalTemplate string

type VersionedConfidentialMetadataTFCode struct {
	core.VersionedConfidentialMetadata
	ObjectSingular      string
	DestinationArgument string
}

func (md *VersionedConfidentialMetadataTFCode) CiphertextAppraisal() string {
	rv, err := Render("ciphertextAppraisal", confidentialDataAppraisalTemplate, md)
	if err != nil {
		return err.Error()
	} else {
		return rv
	}
}
