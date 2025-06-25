package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generateSecretResourceEmptyTags(t *testing.T) string {
	kwp := tfgen.ContentWrappingParams{
		RSAPublicKeyFile: wrappingKey,
		Labels:           "acceptance-testing",
		NoLabels:         false,

		DestinationCoordinate: tfgen.AzKeyVaultObjectCoordinateTFCode{
			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
				Name: "acceptance-test-secret-empty-tags",
			},
		},

		TFBlockName: "secret",
	}

	if vErr := kwp.Validate(); vErr != nil {
		assert.Fail(t, vErr.Error())
	}

	if rv, tfErr := tfgen.OutputSecretTerraformCode(kwp, "this is a very secret string", true, nil); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		print(rv)
		return rv
	}
}

func TestAccConfidentialSecretWithEmptyTags(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generateSecretResourceEmptyTags(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the secret version is set after creation
					resource.TestCheckResourceAttrSet("az-confidential_secret.secret", "secret_version"),
					resource.TestCheckResourceAttr("az-confidential_secret.secret", "enabled", "true"),
				),
			},
		},
	})
}
