// Copyright (c) HashiCorp, Inc.

package tfgen

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Key_OutputSecretTerraformCode_Renders(t *testing.T) {
	_, publicKey := core.GenerateEphemeralKeyPair()
	kwp := ContentWrappingParams{
		LoadedRsaPublicKey: publicKey,
		DestinationCoordinate: AzKeyVaultObjectCoordinateTFCode{
			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
				VaultName: "var.dest_vault_name",
				Name:      "var.dest_object_name",
				Type:      "secret",
			},
			VaultNameIsExpr:  true,
			ObjectNameIsExpr: true,
		},
		WrappingKeyCoordinate: WrappingKeyCoordinateTFCode{
			WrappingKeyCoordinate: core.WrappingKeyCoordinate{
				VaultName:  "var.vault_name",
				KeyName:    "var.key_name",
				KeyVersion: "var.key_version",
			},
			KeyNameIsExpr:    true,
			VaultNameIsExpr:  true,
			KeyVersionIsExpr: true,
		},

		TFBlockName: "rsa_key",
	}

	v, err := OutputKeyTerraformCode(kwp,
		testkeymaterial.EphemeralRsaKeyText,
		"rsa-key",
		basicTags)

	assert.Nil(t, err)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Print(v)
}
