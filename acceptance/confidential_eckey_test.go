package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generatePEMEncodedECKeyResource(t *testing.T) string {
	kwp := tfgen.ContentWrappingParams{
		RSAPublicKeyFile: wrappingKey,
		Labels:           "acceptance-testing",
		NoLabels:         false,

		DestinationCoordinate: tfgen.AzKeyVaultObjectCoordinateTFCode{
			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
				Name: "acceptance-test-ec-key",
			},
		},

		TFBlockName: "ec_key",
	}

	if vErr := kwp.Validate(); vErr != nil {
		assert.Fail(t, vErr.Error())
	}

	tags := map[string]string{
		"a":           "tag_a",
		"environment": "tf_acceptance_test",
	}

	ecKey, ecErr := core.PrivateKeyFromData(testkeymaterial.Secp256r1EcPrivateKey)
	assert.Nil(t, ecErr)

	jwwKey, jwkKeyErr := jwk.Import(ecKey)
	assert.Nil(t, jwkKeyErr)
	if _, ok := jwwKey.(jwk.ECDSAPrivateKey); !ok {
		assert.Fail(t, "Imported key is not EC; the subsequent test should fail")
	}

	if rv, tfErr := tfgen.OutputKeyTerraformCode(kwp,
		jwwKey,
		tags); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		print(rv)
		return rv
	}
}

func TestAccConfidentialECKey(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generatePEMEncodedECKeyResource(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the secret version is set after creation
					resource.TestCheckResourceAttrSet("az-confidential_key.ec_key", "key_version"),
					resource.TestCheckResourceAttrSet("az-confidential_key.ec_key", "public_key_pem"),
					resource.TestCheckResourceAttr("az-confidential_key.ec_key", "enabled", "true"),
				),
			},
		},
	})
}
