package resources

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ConfidentialPasswordModel Model for the encrypted password in the configuration that can be unwrapped into the state file.
type ConfidentialPasswordModel struct {
	WrappedConfidentialMaterialModel
	PlaintextPassword       types.String `tfsdk:"plaintext_password"`
	PlaintextPasswordBase64 types.String `tfsdk:"plaintext_password_b64"`
	PlaintextPasswordHex    types.String `tfsdk:"plaintext_password_hex"`
}

func (cpm *ConfidentialPasswordModel) Accept(unwrappedPayload core.VersionedConfidentialData) {
	// For this example code, hardcoding a response value to
	// save into the Terraform state.
	cpm.Id = types.StringValue(unwrappedPayload.Uuid)
	if len(unwrappedPayload.StringPayload) > 0 {
		strVal := unwrappedPayload.StringPayload

		cpm.PlaintextPassword = types.StringValue(strVal)
		cpm.PlaintextPasswordBase64 = types.StringValue(base64.StdEncoding.EncodeToString([]byte(strVal)))
		cpm.PlaintextPasswordHex = types.StringValue(hex.EncodeToString([]byte(strVal)))
	} else {
		cpm.PlaintextPassword = types.StringNull()
		cpm.PlaintextPasswordBase64 = types.StringNull()
		cpm.PlaintextPasswordHex = types.StringNull()
	}

	if unwrappedPayload.Payload != nil {
		cpm.PlaintextPasswordBase64 = types.StringValue(base64.StdEncoding.EncodeToString(unwrappedPayload.Payload))
		cpm.PlaintextPasswordHex = types.StringValue(hex.EncodeToString(unwrappedPayload.Payload))
	}
}

type ConfidentialPasswordDataSource struct {
	ConfidentialDatasourceBase
}

func (d *ConfidentialPasswordDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password"
}

func (d *ConfidentialPasswordDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	specificAttr := map[string]schema.Attribute{
		"plaintext_password": schema.StringAttribute{
			Description:         "Decrypted password",
			MarkdownDescription: "Decrypted password",
			Computed:            true,
		},
		"plaintext_password_b64": schema.StringAttribute{
			Description:         "Base64-encoded plaintext password (where the password is a byte sequence)",
			MarkdownDescription: "Base64-encoded plaintext password (where the password is a byte sequence)",
			Computed:            true,
		},
		"plaintext_password_hex": schema.StringAttribute{
			Description:         "Hex-encoded plaintext password (where the password is a byte sequence)",
			MarkdownDescription: "Hex-encoded plaintext password (where the password is a byte sequence)",
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

	unwrappedPayload := d.Unwrap(ctx, data.WrappedConfidentialMaterialModel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "diagnostics contain error after unwrapping the ciphertext; cannot continue")
		return
	}

	if unwrappedPayload.Type != "password" {
		resp.Diagnostics.AddError("Mismatching confidential object type", fmt.Sprintf("Expected `password`, received `%s`", unwrappedPayload.Type))
	}

	d.factory.EnsureCanPlace(ctx, unwrappedPayload, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	data.Accept(unwrappedPayload)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if trackErr := d.factory.TrackObjectId(ctx, unwrappedPayload.Uuid); trackErr != nil {
		errMsg := fmt.Sprintf("Could not track the password entered into the state: %s", trackErr.Error())
		tflog.Error(ctx, errMsg)
		resp.Diagnostics.AddError("incoming object tracking", errMsg)
	}
}

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &ConfidentialPasswordDataSource{}

func NewConfidentialPasswordDataSource() datasource.DataSource {
	return &ConfidentialPasswordDataSource{}
}
