// Copyright (c) HashiCorp, Inc.

package core

import "github.com/hashicorp/terraform-plugin-framework/types"

type AzKeyVaultObjectCoordinateModel struct {
	VaultName types.String `tfsdk:"vault_name"`
	Name      types.String `tfsdk:"name"`
}
