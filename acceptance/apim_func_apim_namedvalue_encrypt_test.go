package acceptance

import (
	"crypto/rsa"
	_ "embed"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/stretchr/testify/assert"
	"testing"
)

type EncryptApimNamedValueParams struct {
	BaseEncryptFunctionParameters

	AzSubscriptionId string
	ResourceGroup    string
	ServiceName      string
	NamedValue       string
}

//go:embed templates/apim_func_namedvalue_encrypt_locked.tmpl
var encApimNamedValueFuncTemplate string

//go:embed templates/apim_func_namedvalue_encrypt_unlocked.tmpl
var encApimNamedValueNoLockFuncTemplate string

func TestAccEncryptApimNamedValueWithLock(t *testing.T) {

	params := EncryptApimNamedValueParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:        string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit:      "72h",
			ExpiresAfterDays: 365,
			NumUses:          10,
			ProviderConstraints: []core.ProviderConstraint{
				"test",
			},
		},
		AzSubscriptionId: "azSubId",
		ResourceGroup:    "rg",
		ServiceName:      "serviceName",
		NamedValue:       "nv",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_named_value", encApimNamedValueFuncTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_named_value"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := apim.DecryptNamedValueMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, "named value content", data.GetStingData())

					// Very basic check that time constraints were actually applied.
					assert.True(t, header.CreateLimit > 0)
					assert.True(t, header.Expiry > 0 && header.Expiry > header.CreateLimit)

					assert.Equal(t, 10, header.NumUses)

					assert.True(t, core.SameBag[core.ProviderConstraint](
						func(a, b core.ProviderConstraint) bool { return a == b },
						params.ProviderConstraints,
						header.ProviderConstraints,
					))

					assert.Equal(t, core.PlacementConstraint("az-c-label:///subscriptions/azSubId/resourceGroups/rg/providers/Microsoft.ApiManagement/service/serviceName/namedValues/nv"), header.PlacementConstraints[0])

					return nil
				},
			},
		},
	})
}

func TestAccEncryptApimNamedValueWithoutLock(t *testing.T) {

	params := EncryptApimNamedValueParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:        string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit:      "72h",
			ExpiresAfterDays: 365,
			NumUses:          10,
			ProviderConstraints: []core.ProviderConstraint{
				"test", "acceptance",
			},
		},
		AzSubscriptionId: "azSubId",
		ResourceGroup:    "rg",
		ServiceName:      "serviceName",
		NamedValue:       "nv",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_named_value", encApimNamedValueNoLockFuncTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_named_value"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := apim.DecryptNamedValueMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, "named value content", data.GetStingData())

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
