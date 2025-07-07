package core

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type Consumer[T any] func(T)
type Supplier[T any] func() T
type Locator[T any, V any] func(t *T) V

// GetFirstString get the first string from potentially nullable Terraform models
// The locator function is used to locate a field of interest. The parameter sources
// specify the list of nullable models, in the order of preference.
func GetFirstString[T any](loc Locator[T, types.String], sources ...*T) string {
	for _, s := range sources {
		if s != nil {
			tfVal := loc(s)
			if !tfVal.IsNull() && !tfVal.IsUnknown() {
				return tfVal.ValueString()
			}
		}
	}

	return ""
}

type Mapper[K, V any] func(K) V

func MapSlice[K, V any](mapper Mapper[K, V], inputSlice []K) []V {
	rv := make([]V, len(inputSlice))
	for i, k := range inputSlice {
		rv[i] = mapper(k)
	}

	return rv
}

type Comparator[K any] = func(a, b K) bool
type EquivalenceComparator[K, V any] = func(a K, b V) bool

// ObjectExportSupport support for exporting data to a model-at-rest
type ObjectExportSupport[T, K any] interface {
	Export() (K, error)
	Import(K) (T, error)
	// Value returns the value immediately known
	Value() T
}

func SameBag[K any](comparator Comparator[K], a, b []K) bool {
	if len(a) != len(b) {
		return false
	}

outer:
	for _, aObj := range a {
		for _, bObj := range b {
			if comparator(aObj, bObj) {
				continue outer
			}
		}

		return false
	}

	return true
}

func EquivalentBag[K, V any](comparator EquivalenceComparator[K, V], a []K, b []V) bool {
	if len(a) != len(b) {
		return false
	}

outer:
	for _, aObj := range a {
		for _, bObj := range b {
			if comparator(aObj, bObj) {
				continue outer
			}
		}

		return false
	}

	return true
}
