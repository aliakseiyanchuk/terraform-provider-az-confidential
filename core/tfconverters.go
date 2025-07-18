package core

import (
	"context"
	"errors"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TerraformStringSetAsPtr(ctx context.Context, tf types.Set) []*string {
	if tf.IsNull() || tf.IsUnknown() {
		return nil
	}

	var strArr []string
	tf.ElementsAs(ctx, &strArr, false)

	rv := make([]*string, len(strArr))
	for i, v := range strArr {
		outVal := v
		rv[i] = &outVal
	}

	return rv
}

func CreateEmptyTerraformSet(tfAttrType attr.Type) types.Set {
	elements := make([]attr.Value, 0)
	rv, _ := basetypes.NewSetValue(tfAttrType, elements)
	return rv
}

func ConvertToTerraformSet[K any](mapper Mapper[K, attr.Value], tfAttrType attr.Type, values ...K) (types.Set, error) {
	elements := make([]attr.Value, len(values))
	for i, value := range values {
		elements[i] = mapper(value)
	}

	rv, dg := types.SetValue(tfAttrType, elements)
	var rvErr error
	if dg.HasError() {
		rvErr = errors.New(dg[0].Summary())
	}

	return rv, rvErr
}

func ConvertStingPrtToTerraform(from *string, into *types.String) {
	if from == nil {
		if !IsEmpty(into) {
			*into = types.StringNull()
		}
	} else {
		*into = types.StringValue(*from)
	}
}

func IsEmpty(t *types.String) bool {
	return t.IsUnknown() || t.IsNull() || len(t.ValueString()) == 0
}

func ConvertBoolPrtToTerraform(from *bool, into *types.Bool) {
	if from == nil {
		*into = types.BoolNull()
	} else {
		*into = types.BoolValue(*from)
	}
}

func ConvertMapToTerraform(p map[string]*string, into *basetypes.MapValue) {
	inputMapIsEmpty := p == nil || len(p) == 0
	sourceMapIsEmpty := (*into).IsUnknown() || (*into).IsNull()

	// Do nothing if both input and source maps are empty,
	// These can be used interchangeably. Except if the source map
	// is unknown, it needs to be set into null value.
	if inputMapIsEmpty && sourceMapIsEmpty {
		if (*into).IsUnknown() {
			*into = types.MapNull(types.StringType)
		}
		return
	}

	*into = TerraformMapFromPtrMap(p)
}

func TerraformMapFromPtrMap(p map[string]*string) basetypes.MapValue {
	tfTags := map[string]attr.Value{}

	for k, v := range p {
		if v != nil {
			tfTags[k] = types.StringValue(*v)
		}
	}

	mapVal, _ := types.MapValue(types.StringType, tfTags)
	return mapVal
}

func StringValueOf(v *types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	} else {
		return v.ValueString()
	}
}
