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

type EncryptApimSubscriptionParams struct {
	BaseEncryptFunctionParameters

	PrimaryKey       string
	SecondaryKey     string
	AzSubscriptionId string
	ResourceGroup    string
	ServiceName      string
	SubscriptionId   string
	ApiId            string
	ProductId        string
	UserId           string
}

//go:embed templates/apim_func_subscription_encrypt_locked.tmpl
var funcTemplate string

//go:embed templates/apim_func_subscription_encrypt_unlocked.tmpl
var funcTemplateNoLock string

func TestAccEncryptApimSubscriptionWithProductLock(t *testing.T) {

	params := EncryptApimSubscriptionParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:   string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit: "72h",
			ExpiresIn:   365,
			NumUses:     10,
			ProviderConstraints: []core.ProviderConstraint{
				"test",
			},
		},
		PrimaryKey:       "a",
		SecondaryKey:     "b",
		AzSubscriptionId: "azSubId",
		ResourceGroup:    "rg",
		ServiceName:      "serviceName",
		ProductId:        "productId",
		UserId:           "userId",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_subscription", funcTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_subscription_value"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := apim.DecryptSubscriptionMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, "a", data.GetPrimaryKey())
					assert.Equal(t, "b", data.GetSecondaryKey())

					// Very basic check that time constraints were actually applied.
					assert.True(t, header.CreateLimit > 0)
					assert.True(t, header.Expiry > 0 && header.Expiry > header.CreateLimit)

					assert.Equal(t, 10, header.NumUses)

					assert.True(t, core.SameBag[core.ProviderConstraint](
						func(a, b core.ProviderConstraint) bool { return a == b },
						params.ProviderConstraints,
						header.ProviderConstraints,
					))

					assert.Equal(t, core.PlacementConstraint("az-c-label:///subscriptions/azSubId/resourceGroups/rg/providers/Microsoft.ApiManagement/service/serviceName/subscriptions/?api=/product=productId/user=userId"), header.PlacementConstraints[0])

					return nil
				},
			},
		},
	})
}

func TestAccEncryptApimSubscriptionWithApiLock(t *testing.T) {

	params := EncryptApimSubscriptionParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:   string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit: "72h",
			ExpiresIn:   365,
			NumUses:     10,
			ProviderConstraints: []core.ProviderConstraint{
				"test", "acceptance",
			},
		},
		PrimaryKey:       "a",
		SecondaryKey:     "b",
		AzSubscriptionId: "azSubId",
		ResourceGroup:    "rg",
		ServiceName:      "serviceName",
		ApiId:            "apiId",
		UserId:           "userId",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_subscription", funcTemplate, &params)
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
					v := state.RootModule().Outputs["encrypted_subscription_value"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := apim.DecryptSubscriptionMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, "a", data.GetPrimaryKey())
					assert.Equal(t, "b", data.GetSecondaryKey())

					// Very basic check that time constraints were actually applied.
					assert.True(t, header.CreateLimit > 0)
					assert.True(t, header.Expiry > 0 && header.Expiry > header.CreateLimit)

					assert.Equal(t, 10, header.NumUses)

					assert.True(t, core.SameBag[core.ProviderConstraint](
						func(a, b core.ProviderConstraint) bool { return a == b },
						params.ProviderConstraints,
						header.ProviderConstraints,
					))

					assert.Equal(t, core.PlacementConstraint("az-c-label:///subscriptions/azSubId/resourceGroups/rg/providers/Microsoft.ApiManagement/service/serviceName/subscriptions/?api=apiId/product=/user=userId"), header.PlacementConstraints[0])

					return nil
				},
			},
		},
	})
}

func TestAccEncryptApimSubscriptionWithoutLock(t *testing.T) {

	params := EncryptApimSubscriptionParams{
		BaseEncryptFunctionParameters: BaseEncryptFunctionParameters{
			PublicKey:   string(testkeymaterial.EphemeralRsaPublicKey),
			CreateLimit: "72h",
			ExpiresIn:   365,
			NumUses:     10,
			ProviderConstraints: []core.ProviderConstraint{
				"test", "acceptance",
			},
		},
		PrimaryKey:       "a",
		SecondaryKey:     "b",
		AzSubscriptionId: "azSubId",
		ResourceGroup:    "rg",
		ServiceName:      "serviceName",
		ApiId:            "apiId",
		UserId:           "userId",
	}

	privateKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	tfCode, err := model.Render("encrypt_subscription", funcTemplateNoLock, &params)
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
					v := state.RootModule().Outputs["encrypted_subscription_value"]

					em := core.EncryptedMessage{}
					if importErr := em.FromBase64PEM(v.Value.(string)); importErr != nil {
						return importErr
					}

					header, data, decryptErr := apim.DecryptSubscriptionMessage(
						em,
						func(bytes []byte) ([]byte, error) {
							return core.RsaDecryptBytes(privateKey.(*rsa.PrivateKey), bytes, nil)
						},
					)
					if decryptErr != nil {
						return decryptErr
					}

					assert.Equal(t, "a", data.GetPrimaryKey())
					assert.Equal(t, "b", data.GetSecondaryKey())

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
