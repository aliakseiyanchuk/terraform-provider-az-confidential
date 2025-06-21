package schemasupport

import (
	"context"
	"encoding/base64"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type Base64StringValidator struct {
}

func (b Base64StringValidator) Description(ctx context.Context) string {
	return "Base64 string validator"
}

func (b Base64StringValidator) MarkdownDescription(ctx context.Context) string {
	return "Base64 String validator"
}

func (b Base64StringValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	v := request.ConfigValue.ValueString()
	if _, err := base64.StdEncoding.DecodeString(v); err != nil {
		response.Diagnostics.AddAttributeError(request.Path, "Not a valid Base-64 string", err.Error())
	}
}
