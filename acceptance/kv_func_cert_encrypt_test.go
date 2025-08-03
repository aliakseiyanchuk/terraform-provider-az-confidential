package acceptance

import (
	"crypto/rsa"
	_ "embed"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/segmentio/asm/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

type EncryptKvCertParams struct {
	BaseEncryptFunctionParameters
	KeyVaultDestination
	Certificate string
	Password    string
}

//go:embed templates/kv_func_cert_encrypt_locked.tmpl
var kvCertEncryptTemplate string

//go:embed templates/kv_func_cert_encrypt_unlocked.tmpl
var kvCertEncryptNoLockTemplate string

func TestAccEncryptKvCertWithPlacementLock(t *testing.T) {

	params := EncryptKvCertParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:   string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit: "72h",
			ExpiresIn:   365,
			NumUses:     10,
			ProviderConstraints: []core.ProviderConstraint{
				"test",
			},
		},
		KeyVaultDestination: KeyVaultDestination{
			VaultName:  "VaultName",
			ObjectName: "CertName",
		},
		Certificate: base64.StdEncoding.EncodeToString(testkeymaterial.EphemeralCertificatePEM),
		Password:    "",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_kv_cert", kvCertEncryptTemplate, &params)
	assert.NoError(t, err)

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             tfCode.String(),
				ExpectNonEmptyPlan: true,
				Check: func(state *terraform.State) error {
					v := state.RootModule().Outputs["encrypted_kv_cert"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := keyvault.DecryptCertificateMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, testkeymaterial.EphemeralCertificatePEM, data.GetCertificateData())
					assert.Equal(t, "", data.GetCertificateDataPassword())
					assert.Equal(t, "application/x-pem-file", data.GetCertificateDataFormat())

					// Very basic check that time constraints were actually applied.
					assert.True(t, header.CreateLimit > 0)
					assert.True(t, header.Expiry > 0 && header.Expiry > header.CreateLimit)

					assert.Equal(t, 10, header.NumUses)

					assert.True(t, core.SameBag[core.ProviderConstraint](
						func(a, b core.ProviderConstraint) bool { return a == b },
						params.ProviderConstraints,
						header.ProviderConstraints,
					))

					assert.Equal(t, core.PlacementConstraint("az-c-keyvault://VaultName@certificates=CertName"), header.PlacementConstraints[0])

					return nil
				},
			},
		},
	})
}

func TestAccEncryptKvCertWithoutLock(t *testing.T) {

	params := EncryptKvCertParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:   string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit: "72h",
			ExpiresIn:   365,
			NumUses:     10,
			ProviderConstraints: []core.ProviderConstraint{
				"test", "acceptance",
			},
		},
		Certificate: base64.StdEncoding.EncodeToString(testkeymaterial.EphemeralCertificatePEM),
		Password:    "",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_kv_cert", kvCertEncryptNoLockTemplate, &params)
	assert.NoError(t, err)

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             tfCode.String(),
				ExpectNonEmptyPlan: true,
				Check: func(state *terraform.State) error {
					v := state.RootModule().Outputs["encrypted_kv_cert"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := keyvault.DecryptCertificateMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, testkeymaterial.EphemeralCertificatePEM, data.GetCertificateData())
					assert.Equal(t, "", data.GetCertificateDataPassword())
					assert.Equal(t, "application/x-pem-file", data.GetCertificateDataFormat())

					// Very basic check that time constraints were actually applied.
					assert.True(t, header.CreateLimit > 0)
					assert.True(t, header.Expiry > 0 && header.Expiry > header.CreateLimit)

					assert.Equal(t, 10, header.NumUses)

					assert.True(t, core.SameBag[core.ProviderConstraint](
						func(a, b core.ProviderConstraint) bool { return a == b },
						params.ProviderConstraints,
						header.ProviderConstraints,
					))

					assert.Nil(t, header.PlacementConstraints)

					return nil
				},
			},
		},
	})
}
