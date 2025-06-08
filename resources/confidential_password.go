package resources

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ConfidentialPasswordModel Model for the encrypted password in the configuration that can be unwrapped into the state file.
type ConfidentialPasswordModel struct {
	WrappedConfidentialMaterialModel
	PlaintextPassword       types.String `tfsdk:"plaintext_password"`
	PlaintextPasswordBase64 types.String `tfsdk:"plaintext_password_b64"`
	PlaintextPasswordHex    types.String `tfsdk:"plaintext_password_hex"`
}

type ConfidentialPasswordDataSource struct {
	ConfidentialResourceBase
}

func (d *ConfidentialPasswordDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password"
}

func (d *ConfidentialPasswordDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	specificAttr := map[string]schema.Attribute{
		"plaintext_password": schema.StringAttribute{
			Description:         "Decrypted password available in state",
			MarkdownDescription: "Decrypted password available in state",
			Computed:            true,
		},
		"plaintext_password_b64": schema.StringAttribute{
			Description:         "Base64-encoded plaintext password (where the password is a byte sequence)",
			MarkdownDescription: "Base64-encoded plaintext password (where the password is a byte sequence)",
			Computed:            true,
		},
	}
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Datasource providing password decryption",
		Attributes:          WrappedConfidentialMaterialModelDatasourceSchema(specificAttr),
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Datasource unwrapping a password into state",
		Description:         "Datasource unwrapping password into state",

		Attributes: WrappedConfidentialMaterialModelDatasourceSchema(specificAttr),
	}
}

func (d *ConfidentialPasswordDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ConfidentialPasswordModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	unwrappedPayload := d.Unwrap(ctx, data.WrappedConfidentialMaterialModel, resp.Diagnostics)
	if unwrappedPayload.Type != "password" {
		resp.Diagnostics.AddError("Mismatching confidential object type", fmt.Sprintf("Expected `password`, received `%s`", unwrappedPayload.Type))
	}

	// For this example code, hardcoding a response value to
	// save into the Terraform state.
	data.Id = types.StringValue(unwrappedPayload.Uuid)
	if unwrappedPayload.StringPayload != nil {
		strVal := *unwrappedPayload.StringPayload

		data.PlaintextPassword = types.StringValue(strVal)
		data.PlaintextPasswordBase64 = types.StringValue(base64.StdEncoding.EncodeToString([]byte(strVal)))
		data.PlaintextPasswordHex = types.StringValue(hex.EncodeToString([]byte(strVal)))
	} else {
		data.PlaintextPassword = types.StringNull()
		data.PlaintextPasswordBase64 = types.StringNull()
		data.PlaintextPasswordHex = types.StringNull()
	}

	if unwrappedPayload.Payload != nil {
		data.PlaintextPasswordBase64 = types.StringValue(base64.StdEncoding.EncodeToString(unwrappedPayload.Payload))
		data.PlaintextPasswordHex = types.StringValue(hex.EncodeToString(unwrappedPayload.Payload))
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &ConfidentialPasswordDataSource{}

func NewConfidentialPasswordDataSource() datasource.DataSource {
	return &ConfidentialPasswordDataSource{}
}
