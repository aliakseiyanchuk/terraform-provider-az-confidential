package acceptance

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func NewVarRef(varName string) model.TerraformFieldExpression[string] {
	rv := model.NewStringTerraformFieldExpression()
	rv.SetExpression(fmt.Sprintf("var.%s", varName))

	return rv
}

func NewStrVal(strVal string) model.TerraformFieldExpression[string] {
	rv := model.NewStringTerraformFieldExpression()
	rv.SetValue(strVal)

	return rv
}

func generateApimNamedValueResource(t *testing.T) string {
	kwp := model.ContentWrappingParams{
		SecondaryProtectionParameters: core.SecondaryProtectionParameters{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey:      core.LoadPublicKeyFromFileOnce(wrappingKey),
		WrappingKeyCoordinate: model.NewWrappingKey(),
	}

	nvModel := apim.NamedValueTerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "acc_nv",
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
			EncryptedContent:      model.NewStringTerraformFieldHeredocExpression(),
		},

		Tags: model.KeylessTagsModel{
			IncludeTags: true,
		},

		DestinationNamedValue: apim.NamedValueCoordinateModel{
			BaseCoordinateModel: apim.BaseCoordinateModel{
				AzSubscriptionId:  NewVarRef("az_subscription_id"),
				ResourceGroupName: NewVarRef("az_apim_group_name"),
				ServiceName:       NewVarRef("az_apim_service_name"),
			},
			NamedValue: NewStrVal("tfAcceptanceVal"),
		},
	}

	if rv, _, tfErr := apim.OutputNamedValueTerraformCode(nvModel, &kwp, "this is a very sensitive named value"); tfErr != nil {
		assert.Fail(t, tfErr.Error())
		return rv.String()
	} else {
		//print(rv)
		return rv.String()
	}
}

func TestAccApimNamedValue(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: providerConfig + generateApimNamedValueResource(t),
				Check: resource.ComposeTestCheckFunc(
					// Validate that the secret version is set after creation
					resource.TestCheckResourceAttr("az-confidential_apim_named_value.acc_nv", "display_name", "tfAcceptanceVal"),
				),
			},
		},
	})
}
