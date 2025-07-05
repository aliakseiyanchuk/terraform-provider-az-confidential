package core

import (
	"errors"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

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
