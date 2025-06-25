package tfgen

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

var basicTags = map[string]string{
	"foo":         "bar",
	"environment": "unit-test",
}

func Test_Secret_OutputSecretTerraformCode_Renders(t *testing.T) {
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
	}

	v, err := OutputSecretTerraformCode(kwp, "this is a secret", true, basicTags)
	assert.Nil(t, err)

	fmt.Print(v)
}
