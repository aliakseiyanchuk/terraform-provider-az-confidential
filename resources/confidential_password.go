package resources

import (
	"context"
	_ "embed"
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
	ConfidentialMaterialModel
	PlaintextPassword       types.String `tfsdk:"plaintext_password"`
	PlaintextPasswordBase64 types.String `tfsdk:"plaintext_password_b64"`
	PlaintextPasswordHex    types.String `tfsdk:"plaintext_password_hex"`
}

func (cpm *ConfidentialPasswordModel) Accept(unwrappedPayload core.VersionedStringConfidentialData) {
	// For this example code, hardcoding a response value to
	// save into the Terraform state.
	cpm.Id = types.StringValue(unwrappedPayload.GetUUID())
	if len(unwrappedPayload.GetStingData()) > 0 {
		strVal := unwrappedPayload.GetStingData()

		cpm.PlaintextPassword = types.StringValue(strVal)
		cpm.PlaintextPasswordBase64 = types.StringValue(base64.StdEncoding.EncodeToString([]byte(strVal)))
		cpm.PlaintextPasswordHex = types.StringValue(hex.EncodeToString([]byte(strVal)))
	} else {
		cpm.PlaintextPassword = types.StringNull()
		cpm.PlaintextPasswordBase64 = types.StringNull()
		cpm.PlaintextPasswordHex = types.StringNull()
	}
}

type ConfidentialPasswordDataSource struct {
	ConfidentialDatasourceBase
}

func (d *ConfidentialPasswordDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password"
}

//go:embed confidential_password.md
var passwordDataSourceMarkdownDescription string

func (d *ConfidentialPasswordDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
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
		Description:         "Datasource unwrapping a password into state",
		MarkdownDescription: passwordDataSourceMarkdownDescription,

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

	plainText := d.ExtractConfidentialModelPlainText(ctx, data.ConfidentialMaterialModel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	helper := core.NewVersionedStringConfidentialDataHelper()
	confidentialData, importErr := helper.Import(plainText)
	if importErr != nil {
		tflog.Error(ctx, "diagnostics contain error after unwrapping the ciphertext; cannot continue")
		resp.Diagnostics.AddError(
			"Cannot parse plain text",
			fmt.Sprintf("Plain text could not be parsed for further processing due to this error: %s. Are you specifying correct ciphertext for this datasource?", importErr.Error()),
		)
		return
	}

	if confidentialData.GetType() != "password" {
		resp.Diagnostics.AddError("Mismatching confidential object type", fmt.Sprintf("Expected `password`, received `%s`", confidentialData.GetType()))
	}

	d.factory.EnsureCanPlaceKeyVaultObjectAt(ctx, confidentialData, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	data.Accept(confidentialData)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &ConfidentialPasswordDataSource{}

func NewConfidentialPasswordDataSource() datasource.DataSource {
	return &ConfidentialPasswordDataSource{}
}
