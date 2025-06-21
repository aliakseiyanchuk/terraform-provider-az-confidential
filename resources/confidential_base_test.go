// Copyright (c) HashiCorp, Inc.

package resources

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_WAKVOCMM_StringTypeAsPtr(t *testing.T) {
	obj := WrappedAzKeyVaultObjectConfidentialMaterialModel{}

	assert.Nil(t, obj.StringTypeAsPtr(nil))

	tfNull := types.StringNull()
	tfUnknown := types.StringUnknown()
	tfVal := types.StringValue("abc")
	assert.Nil(t, obj.StringTypeAsPtr(&tfNull))

	assert.Nil(t, obj.StringTypeAsPtr(&tfUnknown))
	assert.NotNil(t, obj.StringTypeAsPtr(&tfVal))
	assert.Equal(t, "abc", *obj.StringTypeAsPtr(&tfVal))
}
