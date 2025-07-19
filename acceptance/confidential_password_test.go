package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generatePasswordDataSource(t *testing.T) string {

	kwp := model.ContentWrappingParams{
		Labels:           []string{"acceptance-testing"},
		LoadRsaPublicKey: core.LoadPublicKeyFromFileOnce(wrappingKey),
	}

	mdl := model.BaseTerraformCodeModel{
		TFBlockName: "password",
	}

	if rv, tfErr := general.OutputDatasourcePasswordTerraformCode(mdl, &kwp, "this is a very secret string"); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		//print(rv)
		return rv
	}
}

func TestAccConfidentialPasswordDataSourceBasicStringConfiguration(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generatePasswordDataSource(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the message is set
					resource.TestCheckResourceAttr("data.az-confidential_password.confidential_password", "plaintext_password", "this is a very secret string"),
				),
			},
		},
	})
}
