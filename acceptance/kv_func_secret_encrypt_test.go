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

type KeyVaultDestination struct {
	VaultName  string
	ObjectName string
}

type EncryptKvSecretParams struct {
	BaseEncryptFunctionParameters
	KeyVaultDestination
}

//go:embed templates/kv_func_secret_encrypt_locked.tmpl
var kvSecretEncryptTemplate string

//go:embed templates/kv_func_secret_encrypt_unlocked.tmpl
var kvSecretEncryptNoLockTemplate string

func TestAccEncryptKvSecretWithPlacementLock(t *testing.T) {

	params := EncryptKvSecretParams{
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
			ObjectName: "SecretName",
		},
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_kv_secret", kvSecretEncryptTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_kv_secret"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := keyvault.DecryptSecretMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, "kv secret", data.GetStingData())

					// Very basic check that time constraints were actually applied.
					assert.True(t, header.CreateLimit > 0)
					assert.True(t, header.Expiry > 0 && header.Expiry > header.CreateLimit)

					assert.Equal(t, 10, header.NumUses)

					assert.True(t, core.SameBag[core.ProviderConstraint](
						func(a, b core.ProviderConstraint) bool { return a == b },
						params.ProviderConstraints,
						header.ProviderConstraints,
					))

					assert.Equal(t, core.PlacementConstraint("az-c-keyvault://VaultName@secrets=SecretName"), header.PlacementConstraints[0])

					return nil
				},
			},
		},
	})
}

func TestAccEncryptKvSecretWithoutLock(t *testing.T) {

	params := EncryptKvSecretParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:   string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit: "72h",
			ExpiresIn:   365,
			NumUses:     10,
			ProviderConstraints: []core.ProviderConstraint{
				"test", "acceptance",
			},
		},
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_kv_secret", kvSecretEncryptNoLockTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_kv_secret"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := keyvault.DecryptSecretMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, "kv secret", data.GetStingData())

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
