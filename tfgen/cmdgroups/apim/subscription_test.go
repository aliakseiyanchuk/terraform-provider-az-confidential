package apim

import (
	"errors"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWillRenderFullSubscriptionModel(t *testing.T) {

	kwp := model.ContentWrappingParams{
		SecondaryProtectionParameters: core.SecondaryProtectionParameters{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey:      core.LoadPublicKeyFromDataOnce(testkeymaterial.EphemeralRsaPublicKey),
		WrappingKeyCoordinate: model.NewWrappingKeyForExpressions("var.vault_name", "var.key_name", "var.key_version"),
	}

	mdl := SubscriptionTerraformCodeModel{
		BaseTerraformCodeModel: model.NewBaseTerraformCodeModel(&kwp, "subscription", "apim subscription", "destination_subscription"),

		DisplayName:  model.NewStringTerraformFieldExpressionWithValue("confidentialSubscription"),
		State:        model.NewStringTerraformFieldExpressionWithValue("submitted"),
		AllowTracing: model.NewBoolTerraformFieldValueExpression(false),

		DestinationSubscription: NewSubscriptionCoordinateModel(
			"sub",
			"rg",
			"service",
			"apimSubId",
			"productId",
			"apiScop",
			"owner",
		),
	}

	v, err := OutputSubscriptionTerraformCode(mdl, &kwp, "a", "b")
	assert.Nil(t, err)
	if err != nil {
		fmt.Println(errors.Unwrap(err))
	}

	fmt.Println(v)
}
