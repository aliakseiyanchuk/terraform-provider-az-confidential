package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	_ "github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generatePFXCertificateResource(t *testing.T) string {

	kwp := model.ContentWrappingParams{
		SecondaryProtectionParameters: core.SecondaryProtectionParameters{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey: core.LoadPublicKeyFromFileOnce(wrappingKey),
	}

	mdl := keyvault.TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "cert",
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		TagsModel: model.TagsModel{
			IncludeTags: false,
		},

		DestinationCoordinate: keyvault.NewObjectCoordinateModel("", "acceptance-test-pfxcert"),
	}

	confData := core.ConfidentialCertConfidentialDataStruct{
		CertificateData:         testkeymaterial.EphemeralCertPFX12,
		CertificateDataFormat:   keyvault.CertFormatPkcs12,
		CertificateDataPassword: "s1cr3t",
	}

	if rv, _, tfErr := keyvault.OutputCertificateTerraformCode(mdl, &kwp, &confData); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv.String()
	} else {
		//print(rv)
		return rv.String()
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
