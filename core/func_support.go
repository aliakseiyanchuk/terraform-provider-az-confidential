package core

import "github.com/hashicorp/terraform-plugin-framework/types"

type Supplier[T any] func() T
type Locator[T any, V any] func(t *T) V

// GetFirstString get the first string from potentially nullable Terraform models
// The locator function is used to locate a field of interest. The parameter sources
// specify the list of nullable models, in the order of preference.
func GetFirstString[T any](loc Locator[T, types.String], sources ...*T) string {
	for _, s := range sources {
		if s != nil {
			tfVal := loc(s)
			return tfVal.ValueString()
		}
	}

	return ""
}
