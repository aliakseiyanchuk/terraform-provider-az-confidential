package acceptance

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func generateApimSubscriptionResourceForAllApis(t *testing.T) string {

	kwp := model.ContentWrappingParams{
		VersionedConfidentialMetadata: core.VersionedConfidentialMetadata{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey:      core.LoadPublicKeyFromFileOnce(wrappingKey),
		WrappingKeyCoordinate: model.NewWrappingKey(),
	}

	mdl := apim.SubscriptionTerraformCodeModel{
		BaseTerraformCodeModel: model.NewBaseTerraformCodeModel(&kwp, "subscription"),

		DisplayName:  model.NewStringTerraformFieldExpressionWithValue("allApiSubscription"),
		State:        model.NewStringTerraformFieldExpressionWithValue("active"),
		AllowTracing: model.NewBoolTerraformFieldValueExpression(false),

		DestinationSubscription: apim.DestinationSubscriptionModel{
			BaseCoordinateModel: apim.BaseCoordinateModel{
				AzSubscriptionId:  model.NewStringTerraformFieldExpression(),
				ResourceGroupName: model.NewStringTerraformFieldExpressionWithExpr("var.az_apim_group_name"),
				ServiceName:       model.NewStringTerraformFieldExpressionWithExpr("var.az_apim_service_name"),
			},
			SubscriptionId: model.NewStringTerraformFieldExpression(),
			ProductId:      model.NewStringTerraformFieldExpression(),
			ApiId:          model.NewStringTerraformFieldExpression(),
			UserId:         model.NewStringTerraformFieldExpression(),
		},
	}

	if rv, tfErr := apim.OutputSubscriptionTerraformCode(mdl, &kwp, "allApiA", "allApiB"); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv
	} else {
		//print(rv)
		return rv
	}
}

func TestAccConfidentialApimSubscriptionForAllApis(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generateApimSubscriptionResourceForAllApis(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the secret version is set after creation
					resource.TestCheckResourceAttrSet("az-confidential_apim_subscription.subscription", "display_name"),
					resource.TestCheckResourceAttrSet("az-confidential_apim_subscription.subscription", "subscription_id"),
				),
			},
		},
	})
}
