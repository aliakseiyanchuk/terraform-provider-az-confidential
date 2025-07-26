package general

import (
	"context"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ConfidentialContentModel Model for the encrypted password in the configuration that can be unwrapped into the state file.
type ConfidentialContentModel struct {
	resources.ConfidentialMaterialModel
	Plaintext       types.String `tfsdk:"plaintext"`
	PlaintextBase64 types.String `tfsdk:"plaintext_b64"`
	PlaintextHex    types.String `tfsdk:"plaintext_hex"`
}

func (cpm *ConfidentialContentModel) Accept(uuid string, unwrappedPayload core.ConfidentialStringData) {
	// For this example code, hardcoding a response value to
	// save into the Terraform state.
	cpm.Id = types.StringValue(uuid)
	if len(unwrappedPayload.GetStingData()) > 0 {
		strVal := unwrappedPayload.GetStingData()

		cpm.Plaintext = types.StringValue(strVal)
		cpm.PlaintextBase64 = types.StringValue(base64.StdEncoding.EncodeToString([]byte(strVal)))
		cpm.PlaintextHex = types.StringValue(hex.EncodeToString([]byte(strVal)))
	} else {
		cpm.Plaintext = types.StringNull()
		cpm.PlaintextBase64 = types.StringNull()
		cpm.PlaintextHex = types.StringNull()
	}
}

type ConfidentialContentDataSource struct {
	resources.ConfidentialDatasourceBase
}

func (d *ConfidentialContentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_content"
}

//go:embed content.md
var passwordDataSourceMarkdownDescription string

func (d *ConfidentialContentDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	specificAttr := map[string]schema.Attribute{
		"plaintext": schema.StringAttribute{
			Description:         "Decrypted content",
			MarkdownDescription: "Decrypted content",
			Computed:            true,
		},
		"plaintext_b64": schema.StringAttribute{
			Description: "Base64-encoded plaintext content",
			Computed:    true,
		},
		"plaintext_hex": schema.StringAttribute{
			Description: "Hex-encoded plaintext content",
			Computed:    true,
		},
	}
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Datasource providing content decryption",
		Attributes:          resources.WrappedConfidentialMaterialModelDatasourceSchema(specificAttr),
	}

	resp.Schema = schema.Schema{
		Description:         "Datasource unwrapping a content into state",
		MarkdownDescription: passwordDataSourceMarkdownDescription,

		Attributes: resources.WrappedConfidentialMaterialModelDatasourceSchema(specificAttr),
	}
}

const PasswordObjectType = "general/password"

func (d *ConfidentialContentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ConfidentialContentModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plainTextGzip := d.ExtractConfidentialModelPlainText(ctx, data.ConfidentialMaterialModel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	plainText, gzipErr := core.GZipDecompress(plainTextGzip)
	if gzipErr != nil {
		resp.Diagnostics.AddError(
			"Plain-text data structure message is not gzip-compressed",
			fmt.Sprintf("Plain-text data structure must be gzip compressed; attempting to perfrom gunzip returend this error: %s. This is an error on the ciphertext preparation. Please use tfgen tool or provider's function to compute the ciphertext", gzipErr.Error()),
		)
		return
	}

	rawMsg := core.ConfidentialDataMessageJson{}
	if jsonErr := json.Unmarshal(plainText, &rawMsg); jsonErr != nil {
		resp.Diagnostics.AddError(
			"Cannot process plain-text data",
			fmt.Sprintf("The plain-text data does not conform to the minimal expected data structure requirements: %s", jsonErr.Error()),
		)

		return
	}

	if rawMsg.Header.Type != PasswordObjectType {
		resp.Diagnostics.AddError("Mismatching confidential object type", fmt.Sprintf("Expected `password`, received `%s`", rawMsg.Header.Type))
	}

	d.CheckCiphertextExpiry(rawMsg, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: also control the number of uses

	d.Factory.EnsureCanPlaceLabelledObjectAt(ctx, rawMsg.Header.ProviderConstraints, nil, "password", nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	helper := core.NewVersionedStringConfidentialDataHelper()
	confidentialData, importErr := helper.Import(rawMsg.ConfidentialData, rawMsg.Header.ModelReference)
	if importErr != nil {
		tflog.Error(ctx, "diagnostics contain error after unwrapping the ciphertext; cannot continue")
		resp.Diagnostics.AddError(
			"Cannot parse plain text",
			fmt.Sprintf("Plain text could not be parsed for further processing due to this error: %s. Are you specifying correct ciphertext for this datasource?", importErr.Error()),
		)
		return
	}

	if len(confidentialData.GetStingData()) == 0 {
		resp.Diagnostics.AddWarning("Empty confidential data", "Confidential data that this password encrypts seems to be empty")
	}

	data.Accept(rawMsg.Header.Uuid, confidentialData)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &ConfidentialContentDataSource{}

func NewConfidentialPasswordDataSource() datasource.DataSource {
	return &ConfidentialContentDataSource{}
}

func NewPasswordEncryptionFunction() function.Function {
	rv := resources.FunctionTemplate[string, int]{
		Name:                "encrypt_content",
		Summary:             "Encrypts a content",
		MarkdownDescription: "Encrypts a content string to be used with az-confidential_content data source",
		ObjectType:          PasswordObjectType,
		DataParameter: function.StringParameter{
			Name:        "password",
			Description: "Password value that should appear in the key vault",
		},
		ConfidentialModelSupplier: func() string { return "" },
		DestinationModelSupplier:  func() *int { return nil },

		CreatEncryptedMessage: func(confidentialModel string, _ *int, md core.VersionedConfidentialMetadata, pubKey *rsa.PublicKey) (core.EncryptedMessage, error) {
			helper := core.NewVersionedStringConfidentialDataHelper()
			helper.CreateConfidentialStringData(confidentialModel, md)
			return helper.ToEncryptedMessage(pubKey)
		},
	}
	return &rv
}
