package apim

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

func givenTypicalNamedValueWrappingParameters(t *testing.T) (NamedValueTerraformCodeModel, model.ContentWrappingParams) {

	kwp := model.ContentWrappingParams{
		VersionedConfidentialMetadata: core.VersionedConfidentialMetadata{
			ProviderConstraints: []core.ProviderConstraint{"acceptance-testing"},
		},
		LoadRsaPublicKey:      core.LoadPublicKeyFromDataOnce(testkeymaterial.EphemeralRsaPublicKey),
		WrappingKeyCoordinate: model.NewWrappingKeyForExpressions("var.vault_name", "var.key_name", "var.key_version"),
	}

	mdl := NamedValueTerraformCodeModel{
		BaseTerraformCodeModel: model.NewBaseTerraformCodeModel(&kwp, "named_value"),

		Tags: model.KeylessTagsModel{
			IncludeTags: true,
			Tags: []string{
				"acceptance-testing",
				"tech-demo",
			},
		},

		DestinationNamedValue: NewNamedValueCoordinateModel(
			"subscription-id",
			"resourceGroupName",
			"apimServiceName",
			"namedValue",
		),
	}

	return mdl, kwp
}

func TestNamedValueWillProduceOutput(t *testing.T) {
	mdl, kwp := givenTypicalNamedValueWrappingParameters(t)
	tfCode, err := OutputNamedValueTerraformCode(mdl, &kwp, "this is a secret named value")

	fmt.Println(tfCode)

	assert.Nil(t, err)
	assert.True(t, len(tfCode) > 100)

}
