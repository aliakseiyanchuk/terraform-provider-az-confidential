package acceptance

import (
	"testing"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func generateSecretResourceEmptyTags(t *testing.T) string {

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
			IncludeTags: true,
			Tags:        map[string]string{},
		},

		DestinationCoordinate: keyvault.NewObjectCoordinateModel("", "acceptance-test-secret-empty-tags"),
	}

	if rv, _, tfErr := keyvault.OutputSecretTerraformCode(secretModel, &kwp, "this is a very secret string"); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv.String()
	} else {
		//print(rv)
		return rv.String()
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
					resource.TestCheckResourceAttrSet("az-confidential_keyvault_secret.secret", "secret_version"),
					resource.TestCheckResourceAttr("az-confidential_keyvault_secret.secret", "enabled", "true"),
				),
			},
		},
	})
}
