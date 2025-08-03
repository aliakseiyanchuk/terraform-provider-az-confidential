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
	"github.com/stretchr/testify/assert"
	"testing"
)

type EncryptKvKeyParams struct {
	BaseEncryptFunctionParameters
	KeyVaultDestination
	PrivateKey string
	Password   string
}

//go:embed templates/kv_func_key_encrypt_locked.tmpl
var kvKeyEncryptTemplate string

//go:embed templates/kv_func_key_encrypt_unlocked.tmpl
var kvKeyEncryptNoLockTemplate string

func TestAccEncryptKvKeyWithPlacementLock(t *testing.T) {

	params := EncryptKvKeyParams{
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
			ObjectName: "KeyName",
		},
		PrivateKey: string(testkeymaterial.EphemeralRsaKeyText),
		Password:   "",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_kv_key", kvKeyEncryptTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_kv_key"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := keyvault.DecryptKeyMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.NotNil(t, data)

					// Very basic check that time constraints were actually applied.
					assert.True(t, header.CreateLimit > 0)
					assert.True(t, header.Expiry > 0 && header.Expiry > header.CreateLimit)

					assert.Equal(t, 10, header.NumUses)

					assert.True(t, core.SameBag[core.ProviderConstraint](
						func(a, b core.ProviderConstraint) bool { return a == b },
						params.ProviderConstraints,
						header.ProviderConstraints,
					))

					assert.Equal(t, core.PlacementConstraint("az-c-keyvault://VaultName@keys=KeyName"), header.PlacementConstraints[0])

					return nil
				},
			},
		},
	})
}

func TestAccEncryptKvKeyWithoutLock(t *testing.T) {

	params := EncryptKvKeyParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:   string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit: "72h",
			ExpiresIn:   365,
			NumUses:     10,
			ProviderConstraints: []core.ProviderConstraint{
				"test", "acceptance",
			},
		},
		PrivateKey: string(testkeymaterial.EphemeralRsaKeyText),
		Password:   "",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_kv_key", kvKeyEncryptNoLockTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_kv_key"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := keyvault.DecryptKeyMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.NotNil(t, data)

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
