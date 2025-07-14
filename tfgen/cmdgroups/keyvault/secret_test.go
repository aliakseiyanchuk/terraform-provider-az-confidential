package keyvault

import (
	"errors"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

var basicTags = map[string]string{
	"foo":         "bar",
	"environment": "unit-test",
}

func Test_Secret_OutputSecretTerraformCode_Renders(t *testing.T) {
	_, publicKey := core.GenerateEphemeralKeyPair()

	kwp := model.ContentWrappingParams{
		Labels:             []string{"acceptance-testing"},
		LoadedRsaPublicKey: publicKey,
	}

	secretModel := TerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "secret",
			CiphertextLabels:      []string{"acceptance-testing"},
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		TagsModel: model.TagsModel{
			IncludeTags: true,
			Tags: map[string]string{
				"a":           "tag_a",
				"environment": "tf_acceptance_test",
			},
		},
	}

	secretModel.WrappingKeyCoordinate.VaultName.SetExpression("var.vault_name")
	secretModel.WrappingKeyCoordinate.KeyName.SetExpression("var.key_name")
	secretModel.WrappingKeyCoordinate.KeyVersion.SetExpression("var.key_version")

	v, err := OutputSecretTerraformCode(secretModel, &kwp, "this is a secret")
	assert.Nil(t, err)
	if err != nil {
		fmt.Println(errors.Unwrap(err))
	}

	fmt.Print(v)
}
