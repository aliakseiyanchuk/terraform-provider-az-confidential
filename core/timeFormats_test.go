// Copyright (c) HashiCorp, Inc.

package core

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestFormatTime(t *testing.T) {
	assert.True(t, FormatTime(nil).IsNull())

	refEpoch := time.Unix(1749158767, 0)
	assert.Equal(t, "2025-06-05T21:26:07Z", FormatTime(&refEpoch).ValueString())
}

func TestParseTime(t *testing.T) {
	assert.Nil(t, ParseTime(types.StringValue("")))

	v := ParseTime(types.StringValue("2025-06-05T21:26:07Z"))
	assert.NotNil(t, v)

	assert.Equal(t, int64(1749158767), v.Unix())
}
