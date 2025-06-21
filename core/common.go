// Copyright (c) HashiCorp, Inc.

package core

func Contains(v string, values []string) bool {
	for _, value := range values {
		if v == value {
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
