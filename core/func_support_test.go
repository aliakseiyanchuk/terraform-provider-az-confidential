// Copyright (c) HashiCorp, Inc.

package core

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

type TFStrSource struct {
	StrVal types.String
}

func Test_GetFirstString(t *testing.T) {
	loc := func(source *TFStrSource) types.String {
		return source.StrVal
	}

	a := TFStrSource{
		StrVal: types.StringValue("a"),
	}
	b := TFStrSource{
		StrVal: types.StringValue("b"),
	}
	n := TFStrSource{
		StrVal: types.StringNull(),
	}
	u := TFStrSource{
		StrVal: types.StringUnknown(),
	}

	v := GetFirstString(loc, nil, &n, &u, &a, &b)
	assert.Equal(t, "a", v)
}
