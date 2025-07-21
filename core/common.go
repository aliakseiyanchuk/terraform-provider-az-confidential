package core

func Contains(v string, values []string) bool {
	for _, value := range values {
		if v == value {
			return true
		}
	}

	return false
}

func ContainsWithComparator[K, V any](values []K, expectedValue V, comparator BiComparator[K, V]) bool {
	for _, value := range values {
		if comparator(value, expectedValue) {
			return true
		}
	}

	return false
}

func AnyIsIn(sourceValues []string, values []string) bool {
	for _, sv := range sourceValues {
		if Contains(sv, values) {
			return true
		}
	}

	return false
}

func AnyIsInWithComparator[T, V any](sourceValues []T, values []V, cmp BiComparator[T, V]) bool {
	for _, sv := range sourceValues {
		for _, cv := range values {
			if cmp(sv, cv) {
				return true
			}
		}
	}

	return false
}
