// Copyright (c) HashiCorp, Inc.

package schemasupport

import (
	"context"
	"encoding/base64"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateStringSetupMethods(t *testing.T) {
	v := Base64StringValidator{}
	ctx := context.Background()

	assert.True(t, len(v.Description(ctx)) > 0)
	assert.True(t, len(v.MarkdownDescription(ctx)) > 0)
}

func TestValidateString_Negative(t *testing.T) {
	v := Base64StringValidator{}

	req := validator.StringRequest{}
	resp := validator.StringResponse{}

	req.ConfigValue = types.StringValue("this is not a valid base64")
	v.ValidateString(context.Background(), req, &resp)
	assert.True(t, resp.Diagnostics.HasError())
}

func TestValidateString_Positive(t *testing.T) {
	v := Base64StringValidator{}

	req := validator.StringRequest{}
	resp := validator.StringResponse{}

	req.ConfigValue = types.StringValue(base64.StdEncoding.EncodeToString([]byte("this is not a valid base64")))
	v.ValidateString(context.Background(), req, &resp)
	assert.False(t, resp.Diagnostics.HasError())
}
