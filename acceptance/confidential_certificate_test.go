package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generatePEMEncodedCertificateResource(t *testing.T) string {
	kwp := tfgen.ContentWrappingParams{
		RSAPublicKeyFile: wrappingKey,
		Labels:           "acceptance-testing",
		NoLabels:         false,

		DestinationCoordinate: tfgen.AzKeyVaultObjectCoordinateTFCode{
			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
				Name: "acceptance-test-pem-cert",
			},
		},

		TFBlockName: "cert",
	}

	if vErr := kwp.Validate(); vErr != nil {
		assert.Fail(t, vErr.Error())
	}

	tags := map[string]string{
		"a":           "tag_a",
		"environment": "tf_acceptance_test",
	}

	if rv, tfErr := tfgen.OutputConfidentialCertificateTerraformCode(kwp,
		testkeymaterial.EphemeralCertificatePEM,
		"", tags); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		//print(rv)
		return rv
	}
}

func TestAccConfidentialPEMEncodedCertificate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generatePEMEncodedCertificateResource(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the secret version is set after creation
					resource.TestCheckResourceAttrSet("az-confidential_certificate.cert", "secret_id"),
					resource.TestCheckResourceAttrSet("az-confidential_certificate.cert", "versionless_secret_id"),
					resource.TestCheckResourceAttrSet("az-confidential_certificate.cert", "version"),
					resource.TestCheckResourceAttrSet("az-confidential_certificate.cert", "thumbprint"),
					resource.TestCheckResourceAttrSet("az-confidential_certificate.cert", "certificate_data"),
					resource.TestCheckResourceAttrSet("az-confidential_certificate.cert", "certificate_data_base64"),
					resource.TestCheckResourceAttr("az-confidential_certificate.cert", "enabled", "true"),
				),
			},
		},
	})
}
