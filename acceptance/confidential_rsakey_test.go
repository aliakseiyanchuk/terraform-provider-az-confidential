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

func generatePEMEncodedRsaKeyResource(t *testing.T) string {
	kwp := tfgen.ContentWrappingParams{
		RSAPublicKeyFile: wrappingKey,
		Labels:           "acceptance-testing",
		NoLabels:         false,

		DestinationCoordinate: tfgen.AzKeyVaultObjectCoordinateTFCode{
			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
				Name: "acceptance-test-rsa-key",
			},
		},

		TFBlockName: "rsa_key",
	}

	if vErr := kwp.Validate(); vErr != nil {
		assert.Fail(t, vErr.Error())
	}

	tags := map[string]string{
		"a":           "tag_a",
		"environment": "tf_acceptance_test",
	}

	rsaKey, rsaErr := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.Nil(t, rsaErr)

	jwwKey, jwkKeyErr := jwk.Import(rsaKey)
	assert.Nil(t, jwkKeyErr)
	if _, ok := jwwKey.(jwk.RSAPrivateKey); !ok {
		assert.Fail(t, "Imported key is not RSA; the subsequent test should fail")
	}

	if rv, tfErr := tfgen.OutputKeyTerraformCode(kwp,
		jwwKey,
		tags); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		//print(rv)
		return rv
	}
}

func TestAccConfidentialRsaKey(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generatePEMEncodedRsaKeyResource(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the secret version is set after creation
					resource.TestCheckResourceAttrSet("az-confidential_key.rsa_key", "key_version"),
					resource.TestCheckResourceAttrSet("az-confidential_key.rsa_key", "public_key_pem"),
					resource.TestCheckResourceAttr("az-confidential_key.rsa_key", "enabled", "true"),
				),
			},
		},
	})
}
