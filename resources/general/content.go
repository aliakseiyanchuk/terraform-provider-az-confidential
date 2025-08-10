package general

import (
	"context"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

func (cpm *ConfidentialContentModel) Drop() {
	cpm.Plaintext = types.StringValue("----- N/A ------")
	cpm.PlaintextBase64 = types.StringNull()
	cpm.PlaintextHex = types.StringNull()
}

type ConfidentialContentDataSource struct {
	resources.ConfidentialDatasourceBase
}

func (d *ConfidentialContentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_general_content"
}

//go:embed content.md
var contentDataSourceMarkdownDescription string

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
		MarkdownDescription: contentDataSourceMarkdownDescription,

		Attributes: resources.WrappedConfidentialMaterialModelDatasourceSchema(specificAttr),
	}
}

const ContentObjectType = "general/content"

func CreateContentEncryptedMessage(confidentialContent string, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, error) {
	helper := core.NewVersionedStringConfidentialDataHelper(ContentObjectType)

	helper.CreateConfidentialStringData(confidentialContent, md)
	return helper.ToEncryptedMessage(pubKey)
}

func DecryptContentMessage(em core.EncryptedMessage, decrypted core.RSADecrypter) (core.ConfidentialDataJsonHeader, core.ConfidentialStringData, error) {
	helper := core.NewVersionedStringConfidentialDataHelper(ContentObjectType)

	err := helper.FromEncryptedMessage(em, decrypted)
	return helper.Header, helper.KnowValue, err
}

func (d *ConfidentialContentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ConfidentialContentModel

	// Read Terraform configuration data into the model
	dg := &resp.Diagnostics
	dg.Append(req.Config.Get(ctx, &data)...)
	if dg.HasError() {
		return
	}

	em := core.EncryptedMessage{}
	if emImportErr := em.FromBase64PEM(data.EncryptedSecret.ValueString()); emImportErr != nil {
		dg.AddError(
			"Confidential content does not conform to the expected format",
			fmt.Sprintf("Received this error while trying to parse the confidential message: %s. Confidential content shoud be produced either by tfgen tool or vai appropriate function", emImportErr.Error()),
		)
		return
	}

	header, content, err := DecryptContentMessage(em, d.Factory.GetDecrypterFor(ctx, data.WrappingKeyCoordinate))
	if err != nil {
		dg.AddError(
			"Cannot process plain-text data",
			fmt.Sprintf("The plain-text data does not conform to the minimal expected data structure requirements: %s", err.Error()),
		)

		return
	}

	d.CheckUnpackCondition(ctx, header, dg)

	if len(content.GetStingData()) == 0 {
		dg.AddWarning("Empty confidential data", "Confidential data that this content encrypts seems to be empty")
	}

	if !dg.HasError() {
		data.Accept(header.Uuid, content)
	} else {
		data.Drop()
	}

	dg.Append(resp.State.Set(ctx, &data)...)

	if header.NumUses > 0 {
		if trackErr := d.Factory.TrackObjectId(ctx, header.Uuid); trackErr != nil {
			dg.AddError(
				"Content usage cannot be tracked",
				fmt.Sprintf("This content has a limit as to how much time it can be read. Trackign the usage returned this error: %s", trackErr.Error()),
			)
		}
	}
}

func (d *ConfidentialContentDataSource) CheckUnpackCondition(ctx context.Context, header core.ConfidentialDataJsonHeader, dg *diag.Diagnostics) {
	d.CheckCiphertextExpiry(ctx, header, dg)
	if dg.HasError() {
		return
	}

	d.Factory.EnsureCanPlaceLabelledObjectAt(ctx, header.ProviderConstraints, nil, ContentObjectType, nil, dg)
	if dg.HasError() {
		return
	}

	if header.NumUses > 0 {
		if !d.Factory.IsObjectTrackingEnabled() {
			dg.AddError(
				"Object tracking is not enabled",
				"This content has a limit as to how many times it can be read. Enable object tracking in the provider configuration",
			)
		} else {
			if numUses, useCheckErr := d.Factory.GetTackedObjectUses(ctx, header.Uuid); useCheckErr != nil {
				dg.AddError(
					"Object tracking errored",
					fmt.Sprintf("This content has a limit as to how many times it can be read. Attempting to read usage returned this error: %s", useCheckErr.Error()),
				)
			} else if numUses >= header.NumUses {
				dg.AddError(
					"Content usage limit has been reached",
					fmt.Sprintf("This content has a limit as to how many times it can be read, and limit has been reached. Re-encrypt original content and replace the ciphertext to continue"),
				)
			} else if header.NumUses-numUses < 10 {
				dg.AddWarning(
					"Content use is almost depleted",
					fmt.Sprintf("This content has a limit as to how many times it can be read, and this limit is almost reached. Re-encrypt original content and replace the ciphertext to prevent plan/apply runs failing due to depleted usage"),
				)
			}
		}
	}
}

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &ConfidentialContentDataSource{}

func NewConfidentialPasswordDataSource() datasource.DataSource {
	return &ConfidentialContentDataSource{}
}

func NewPasswordEncryptionFunction() function.Function {
	rv := resources.FunctionTemplate[string, resources.ProtectionParams, int]{
		Name:                        "encrypt_general_content",
		Summary:                     "Encrypts a content",
		MarkdownDescription:         "Generates the encrypted (cipher text) version of a content string which then van can be used by `az-confidential_content` data source to unpack this value into the Terraform state",
		ProtectionParameterSupplier: func() resources.ProtectionParams { return resources.ProtectionParams{} },
		DataParameter: function.StringParameter{
			Name:        "content",
			Description: "Content value that should unpacked into the provider's state",
		},
		ConfidentialModelSupplier: func() string { return "" },
		DestinationModelSupplier:  func() *int { return nil },

		CreatEncryptedMessage: func(confidentialContent string, _ *int, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, error) {
			// Content is never created; it's limit is always set to zero. Content can only expire.
			md.CreateLimit = 0
			return CreateContentEncryptedMessage(confidentialContent, md, pubKey)
		},
	}
	return &rv
}
