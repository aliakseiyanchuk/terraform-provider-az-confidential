package acceptance

import (
	"testing"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
)

func generateContentDataSource(t *testing.T) string {

	kwp := model.ContentWrappingParams{
		SecondaryProtectionParameters: core.SecondaryProtectionParameters{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey: core.LoadPublicKeyFromFileOnce(wrappingKey),
	}

	mdl := model.BaseTerraformCodeModel{
		TFBlockName: "content",
	}

	if rv, _, tfErr := general.OutputDatasourceContentTerraformCode(mdl, &kwp, "this is a very secret string"); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv.String()
	} else {
		//print(rv)
		return rv.String()
	}
}

func TestAccConfidentialContentDataSourceBasicStringConfiguration(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generateContentDataSource(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the message is set
					resource.TestCheckResourceAttr("data.az-confidential_general_content.content", "plaintext", "this is a very secret string"),
				),
			},
		},
	})
}
