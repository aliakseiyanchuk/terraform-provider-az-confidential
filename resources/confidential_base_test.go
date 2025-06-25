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

func Test_WAKVOCMM_ConvertAzMap_NullOverEmptyMapIsIdempotent(t *testing.T) {
	refType := WrappedAzKeyVaultObjectConfidentialMaterialModel{}

	emptyMap := map[string]*string{}
	refType.Tags = ConvertStringPtrMapToTerraform(emptyMap)

	refType.ConvertAzMap(nil, &refType.Tags)

	assert.False(t, refType.Tags.IsNull())
}

func Test_WAKVOCMM_ConvertAzMap_EmptyOverNullMapIsIdempotent(t *testing.T) {
	refType := WrappedAzKeyVaultObjectConfidentialMaterialModel{}
	refType.Tags = types.MapNull(types.StringType)

	emptyMap := map[string]*string{}

	refType.ConvertAzMap(emptyMap, &refType.Tags)

	// There is no change: the original map is still null.
	assert.True(t, refType.Tags.IsNull())
}

func Test_WAKVOCMM_ConvertAzMap_NonEmptyMapOverNullChanges(t *testing.T) {
	refType := WrappedAzKeyVaultObjectConfidentialMaterialModel{}
	refType.Tags = types.MapNull(types.StringType)

	v := "abc"
	singleEntryMap := map[string]*string{
		"a": &v,
	}

	refType.ConvertAzMap(singleEntryMap, &refType.Tags)

	// There is no change: the original map is still null.
	assert.False(t, refType.Tags.IsNull())
	assert.Equal(t, 1, len(refType.Tags.Elements()))
}

func Test_WAKVOCMM_ConvertAzMap_EmptyMapOverUnknownWillBeNull(t *testing.T) {
	refType := WrappedAzKeyVaultObjectConfidentialMaterialModel{}
	refType.Tags = types.MapUnknown(types.StringType)

	refType.ConvertAzMap(nil, &refType.Tags)

	// There is no change: the original map is still null.
	assert.False(t, refType.Tags.IsUnknown())
	assert.True(t, refType.Tags.IsNull())
}
