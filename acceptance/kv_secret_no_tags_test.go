package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generateSecretResourceNoTags(t *testing.T) string {

	kwp := model.ContentWrappingParams{
		SecondaryProtectionParameters: core.SecondaryProtectionParameters{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey: core.LoadPublicKeyFromFileOnce(wrappingKey),
	}

	secretModel := keyvault.TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "secret",
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		TagsModel: model.TagsModel{
			IncludeTags: false,
		},

		DestinationCoordinate: keyvault.NewObjectCoordinateModel("", "acceptance-test-secret-notags"),
	}

	if rv, tfErr := keyvault.OutputSecretTerraformCode(secretModel, &kwp, "this is a very secret string"); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		//print(rv)
		return rv
	}
}

func TestAccConfidentialSecretWithoutTags(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generateSecretResourceNoTags(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the secret version is set after creation
					resource.TestCheckResourceAttrSet("az-confidential_secret.secret", "secret_version"),
					resource.TestCheckResourceAttr("az-confidential_secret.secret", "enabled", "true"),
				),
			},
		},
	})
}
