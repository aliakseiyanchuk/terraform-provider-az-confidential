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

func generatePFXCertificateResource(t *testing.T) string {
	kwp := tfgen.ContentWrappingParams{
		RSAPublicKeyFile: wrappingKey,
		Labels:           "acceptance-testing",
		NoLabels:         false,

		DestinationCoordinate: tfgen.AzKeyVaultObjectCoordinateTFCode{
			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
				Name: "acceptance-test-pem-cert-pkcs12",
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
		testkeymaterial.EphemeralCertPFX12, // this is a PKCS12 bag certificate
		tfgen.CERT_FORMAT_PKCS12,           // the certificate format is PKCS12
		"s1cr3t",                           // password is not required
		tags); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		//print(rv)
		return rv
	}
}

func TestAccConfidentialPKCS12File(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generatePFXCertificateResource(t),
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
