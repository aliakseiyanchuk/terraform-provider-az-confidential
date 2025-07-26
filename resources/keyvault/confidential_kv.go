package keyvault

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// Models that could be used in combination with the Terraform identity.

type AzKeyVaultObjectIdentityModel struct {
	VaultName     string `tfsdk:"vault_name"`
	ObjectType    string `tfsdk:"object_type"`
	ObjectName    string `tfsdk:"object_name"`
	ObjectVersion string `tfsdk:"object_version"`
}

func AzKeyVaultObjectIdentityModelSchema() identityschema.Schema {
	return identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"vault_name":     schema.StringAttribute{},
			"object_type":    schema.StringAttribute{},
			"object_name":    schema.StringAttribute{},
			"object_version": schema.StringAttribute{},
		},
	}
}

func (a *AzKeyVaultObjectIdentityModel) AsCoordinate() core.AzKeyVaultObjectVersionedCoordinate {
	return core.AzKeyVaultObjectVersionedCoordinate{
		AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
			VaultName: a.VaultName,
			Name:      a.ObjectName,
			Type:      a.ObjectType,
		},
		Version: a.ObjectVersion,
	}
}
