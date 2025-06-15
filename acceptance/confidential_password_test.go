package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generatePasswordDataSource(t *testing.T) string {
	kwp := tfgen.KeyWrappingParams{
		RSAPublicKeyFile: wrappingKey,
		Labels:           "acceptance-testing",
		NoLabels:         false,
	}

	if vErr := kwp.Validate(); vErr != nil {
		assert.Fail(t, vErr.Error())
	}

	if rv, tfErr := tfgen.OutputDatasourcePasswordTerraformCode(kwp, "this is a very secret string"); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		print(rv)
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
