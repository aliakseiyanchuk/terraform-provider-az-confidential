package resources

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/schemasupport"
	tfstringvalidators "github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	datasourceSchema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceSchema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"time"
)

// Basis for the confidential object processing and creation.

type WrappedConfidentialMaterialModel struct {
	Id types.String `tfsdk:"id"`

	WrappingKeyCoordinate *core.WrappingKeyCoordinateModel `tfsdk:"wrapping_key"`

	EncryptedSecret     types.String `tfsdk:"content"`
	SecretEncryptionKey types.String `tfsdk:"content_encryption_key"`
}

// WrappedAzKeyVaultObjectConfidentialMaterialModel a model for the Azure KeyVault
// object. It includes wrapped confidential data and repeated elements (not-before, not-after,
// tags, and enabled)
type WrappedAzKeyVaultObjectConfidentialMaterialModel struct {
	WrappedConfidentialMaterialModel

	Tags      types.Map    `tfsdk:"tags"`
	NotBefore types.String `tfsdk:"not_before_date"`
	NotAfter  types.String `tfsdk:"not_after_date"`
	Enabled   types.Bool   `tfsdk:"enabled"`
}

func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) TagsAsPtr() map[string]*string {
	if cm.Tags.IsNull() {
		return nil
	}

	rawVals := cm.Tags.Elements()
	if len(rawVals) == 0 {
		return nil
	}

	rv := map[string]*string{}

	for k, v := range rawVals {
		if strAttr, ok := v.(types.String); ok {
			valueString := strAttr.ValueString()
			rv[k] = &valueString
		}
	}

	return rv
}

func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) NotBeforeDateAtPtr() *time.Time {
	return core.ParseTime(cm.NotBefore)
}
func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) NotAfterDateAtPtr() *time.Time {
	return core.ParseTime(cm.NotAfter)
}

func WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(oreAttrs map[string]resourceSchema.Attribute) map[string]resourceSchema.Attribute {
	azObjectAttrs := map[string]resourceSchema.Attribute{
		"enabled": resourceSchema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Whether the version is enabled or not",
		},

		"tags": resourceSchema.MapAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Set of tags to be assigned to this secret",
			ElementType: types.StringType,
		},

		"not_before_date": resourceSchema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Secret not usable before the provided UTC datetime (Y-m-d'T'H:M:S'Z')",
			Validators: []validator.String{
				tfstringvalidators.RegexMatches(validDateTime, "String must be a Y-m-d'T'H:M:S'Z' expression (in Zulu time)"),
			},
		},

		"not_after_date": resourceSchema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Secret not usable before the provided UTC datetime (Y-m-d'T'H:M:S'Z')",
			Validators: []validator.String{
				tfstringvalidators.RegexMatches(validDateTime, "String must be a Y-m-d'T'H:M:S'Z' expression (in Zulu time)"),
			},
		},
	}

	baseSchema := WrappedConfidentialMaterialModelSchema(azObjectAttrs)

	for k, v := range oreAttrs {
		baseSchema[k] = v
	}

	return baseSchema
}

func WrappedConfidentialMaterialModelSchema(moreAttrs map[string]resourceSchema.Attribute) map[string]resourceSchema.Attribute {
	baseSchema := map[string]resourceSchema.Attribute{
		"id": resourceSchema.StringAttribute{
			MarkdownDescription: "Identifier of the decryption operation",
			Computed:            true,
		},

		"wrapping_key": resourceSchema.SingleNestedAttribute{
			Optional:            true,
			Description:         "Wrapping key to use for key and secret unwrapping purposes",
			MarkdownDescription: "Wrapping key to use for key and secret unwrapping purposes",

			Attributes: map[string]resourceSchema.Attribute{
				"vault_name": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Vault name containing the wrapping key",
				},
				"name": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Name of the wrapping key",
				},
				"version": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Version of the wrapping key to use for unwrapping operations",
				},
				"algorithm": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Algorithm to use for unwrapping secret/content encryption key",
				},
			},

			PlanModifiers: []planmodifier.Object{
				objectplanmodifier.RequiresReplace(),
			},
		},

		"content": resourceSchema.StringAttribute{
			MarkdownDescription: "Encrypted secret value",
			Required:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
			Validators: []validator.String{
				schemasupport.Base64StringValidator{},
			},
		},

		"content_encryption_key": resourceSchema.StringAttribute{
			MarkdownDescription: "Encrypted value for the SYMMETRIC key used to encrypt secret where the secret " +
				"value exceeds the capacity of RSA encryption",
			Required: false,
			Optional: true,

			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},

			Validators: []validator.String{
				schemasupport.Base64StringValidator{},
			},
		},
	}

	for k, v := range moreAttrs {
		baseSchema[k] = v
	}

	return baseSchema
}
func WrappedConfidentialMaterialModelDatasourceSchema(moreAttrs map[string]datasourceSchema.Attribute) map[string]datasourceSchema.Attribute {
	baseSchema := map[string]datasourceSchema.Attribute{
		"id": resourceSchema.StringAttribute{
			MarkdownDescription: "Identifier of the decryption operation",
			Computed:            true,
		},

		"wrapping_key": datasourceSchema.SingleNestedAttribute{
			Optional:            true,
			Description:         "Wrapping key to use for key and secret unwrapping purposes",
			MarkdownDescription: "Wrapping key to use for key and secret unwrapping purposes",

			Attributes: map[string]datasourceSchema.Attribute{
				"vault_name": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Vault name containing the wrapping key",
				},
				"name": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Name of the wrapping key",
				},
				"version": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Version of the wrapping key to use for unwrapping operations",
				},
				"algorithm": resourceSchema.StringAttribute{
					Optional:    true,
					Description: "Algorithm to unwrap the secret/content encryption key material",
				},
			},
		},

		"content": datasourceSchema.StringAttribute{
			MarkdownDescription: "Encrypted secret value",
			Required:            true,
			Validators: []validator.String{
				schemasupport.Base64StringValidator{},
			},
		},

		"content_encryption_key": datasourceSchema.StringAttribute{
			MarkdownDescription: "Encrypted value for the SYMMETRIC key used to encrypt secret where the secret " +
				"value exceeds the capacity of RSA encryption",
			Required: false,
			Optional: true,

			Validators: []validator.String{
				schemasupport.Base64StringValidator{},
			},
		},
	}

	for k, v := range moreAttrs {
		baseSchema[k] = v
	}

	return baseSchema
}

func (cm *WrappedConfidentialMaterialModel) GetEncryptedTextValue() []byte {
	v := cm.EncryptedSecret.ValueString()
	if len(v) == 0 {
		return nil
	} else {
		rv, _ := base64.StdEncoding.DecodeString(v)
		return rv
	}
}

func (cm *WrappedConfidentialMaterialModel) GetEncryptedWrappingKeyValue() []byte {
	v := cm.SecretEncryptionKey.ValueString()
	if len(v) == 0 {
		return nil
	} else {
		rv, _ := base64.StdEncoding.DecodeString(v)
		return rv
	}
}

type ConfidentialResourceBase struct {
	factory core.AZClientsFactory
}

func (d *ConfidentialResourceBase) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		tflog.Trace(ctx, "Confidential Az Vault Secret datasource configuration is deferred: provider not yet configured")
		return
	}

	tflog.Debug(ctx, "Attempting to configure confidential Az Vault Secret resource")
	factory, ok := req.ProviderData.(core.AZClientsFactory)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected provider.AZClientsFactory, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.factory = factory
}

func (d *ConfidentialResourceBase) Unwrap(ctx context.Context, mdl WrappedConfidentialMaterialModel, diagnostics diag.Diagnostics) core.VersionedConfidentialData {
	// To create a secret, a coordinate of the wrapping key needs to be established and known
	wrappingKeyCoordinate := d.factory.GetMergedWrappingKeyCoordinate(ctx, mdl.WrappingKeyCoordinate, diagnostics)
	if diagnostics.HasError() {
		return core.VersionedConfidentialData{}
	}

	wrappedText := core.WrappedPlainText{
		EncryptedText:         mdl.GetEncryptedTextValue(),
		EncryptedContentKey:   mdl.GetEncryptedWrappingKeyValue(),
		WrappingKeyCoordinate: wrappingKeyCoordinate,
	}

	plainTextBytes, decrErr := wrappedText.Unwrap(ctx, d.factory)
	if decrErr != nil {
		diagnostics.AddError("Error unwrapping encrypted secret data", decrErr.Error())
		return core.VersionedConfidentialData{}
	}

	tflog.Trace(ctx, "Confidential payload has been unwrapped")

	unwrappedPayload, unwrapError := core.UnwrapPayload(plainTextBytes)
	if unwrapError != nil {
		diagnostics.AddError("error unwrapping secret value", unwrapError.Error())
		return core.VersionedConfidentialData{}
	}
	if objIsTracked, trackerCheckErr := d.factory.IsObjectIdTracked(ctx, unwrappedPayload.Uuid); trackerCheckErr != nil {
		diagnostics.AddError("cannot check tracking status of this secret", trackerCheckErr.Error())
		return core.VersionedConfidentialData{}
	} else if objIsTracked {
		diagnostics.AddError("secret is already tracked", "Potential malfeasance detected: someone is trying to create a secret from records that were previously used")
		return core.VersionedConfidentialData{}
	}

	return unwrappedPayload
}
