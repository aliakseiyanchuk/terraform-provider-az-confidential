package resources

import (
	"context"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/schemasupport"
	tfstringvalidators "github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceSchema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceSchema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"regexp"
	"time"
)

type StateFlushFlag bool

const (
	FlushState      StateFlushFlag = true
	DoNotFlushState StateFlushFlag = false
)

var validDateTime = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z`)

// Basis for the confidential object processing and creation.

type ConfidentialMaterialModel struct {
	Id types.String `tfsdk:"id"`

	WrappingKeyCoordinate *core.WrappingKeyCoordinateModel `tfsdk:"wrapping_key"`

	EncryptedSecret types.String `tfsdk:"content"`
}

func (wcmmm *ConfidentialMaterialModel) SetContainsValues(s *types.Set) bool {
	return !s.IsNull() && !s.IsUnknown() && len(s.Elements()) > 0
}

func (wcmm *ConfidentialMaterialModel) GetDestinationCoordinateFromId() (core.AzKeyVaultObjectVersionedCoordinate, error) {
	rv := core.AzKeyVaultObjectVersionedCoordinate{}
	err := rv.FromId(wcmm.Id.ValueString())
	return rv, err
}

// WrappedAzKeyVaultObjectConfidentialMaterialModel a model for the Azure KeyVault
// object. It includes wrapped confidential data and repeated elements (not-before, not-after,
// tags, and enabled)
type WrappedAzKeyVaultObjectConfidentialMaterialModel struct {
	ConfidentialMaterialModel

	Tags      types.Map    `tfsdk:"tags"`
	NotBefore types.String `tfsdk:"not_before_date"`
	NotAfter  types.String `tfsdk:"not_after_date"`
	Enabled   types.Bool   `tfsdk:"enabled"`
}

func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) StringTypeAsPtr(tfVal *types.String) *string {
	if tfVal == nil {
		return nil
	} else if tfVal.IsNull() || tfVal.IsUnknown() {
		return nil
	} else {
		rv := tfVal.ValueString()
		return &rv
	}
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

func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) TagsAsStr() map[string]string {
	if cm.Tags.IsNull() {
		return nil
	}

	rawVals := cm.Tags.Elements()
	if len(rawVals) == 0 {
		return nil
	}

	rv := map[string]string{}

	for k, v := range rawVals {
		if strAttr, ok := v.(types.String); ok {
			valueString := strAttr.ValueString()
			rv[k] = valueString
		}
	}

	return rv
}

func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) ConvertAzMap(p map[string]*string, into *basetypes.MapValue) {
	inputMapIsEmpty := p == nil || len(p) == 0
	sourceMapIsEmpty := (*into).IsUnknown() || (*into).IsNull()

	// Do nothing if both input and source maps are empty,
	// These can be used interchangeably. Except if the source map
	// is unknown, it needs to be set into null value.
	if inputMapIsEmpty && sourceMapIsEmpty {
		if (*into).IsUnknown() {
			*into = types.MapNull(types.StringType)
		}
		return
	}

	*into = ConvertStringPtrMapToTerraform(p)
}

func ConvertStringPtrMapToTerraform(p map[string]*string) basetypes.MapValue {
	tfTags := map[string]attr.Value{}

	for k, v := range p {
		if v != nil {
			tfTags[k] = types.StringValue(*v)
		}
	}

	mapVal, _ := types.MapValue(types.StringType, tfTags)
	return mapVal
}

func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) ConvertAzString(p *string, into *basetypes.StringValue) {
	if p == nil {
		*into = types.StringNull()
	} else {
		*into = types.StringValue(*p)
	}
}

func (cm *WrappedAzKeyVaultObjectConfidentialMaterialModel) ConvertAzBool(p *bool, into *basetypes.BoolValue) {
	if p == nil {
		*into = types.BoolNull()
	} else {
		*into = types.BoolValue(*p)
	}
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
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
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
	}

	for k, v := range moreAttrs {
		baseSchema[k] = v
	}

	return baseSchema
}

// CommonConfidentialResource common methods for all confidential resources
type CommonConfidentialResource struct {
	factory core.AZClientsFactory
}

func (d *CommonConfidentialResource) ExtractConfidentialModelPlainText(ctx context.Context, mdl ConfidentialMaterialModel, diagnostics *diag.Diagnostics) []byte {
	if d.factory == nil {
		diagnostics.AddError("incomplete provider configuration", "provider does no have an initialized Azure objects factory")
		return nil
	}

	// To create a secret, a coordinate of the wrapping key needs to be established and known
	wrappingKeyCoordinate := d.factory.GetMergedWrappingKeyCoordinate(ctx, mdl.WrappingKeyCoordinate, diagnostics)
	if diagnostics.HasError() {
		tflog.Error(ctx, "Wrapping key coordinate resulted in error diagnostics; this is probably incomplete/inconsistent configuration")
		return nil
	}

	em := core.EncryptedMessage{}
	if emErr := em.FromBase64PEM(mdl.EncryptedSecret.ValueString()); emErr != nil {
		diagnostics.AddError("Invalid encrypted message", fmt.Sprintf("Encrypted message cannot be read from input: %s", emErr.Error()))
		return nil
	}

	payloadBytes, pbErr := em.ExtractPlainText(d.factory.GetDecrypterFor(ctx, wrappingKeyCoordinate))
	if pbErr != nil {
		diagnostics.AddError("Failed to decrypt message", fmt.Sprintf("Encrypted message cannot be decrypted: %s", pbErr.Error()))
		return nil
	}

	return payloadBytes
}

type ConfidentialDatasourceBase struct {
	CommonConfidentialResource
}

func (d *ConfidentialDatasourceBase) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ConfidentialDatasourceBase) FlushState(ctx context.Context, uuid string, data interface{}, resp *datasource.ReadResponse) {
	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

type ConfidentialResourceBase struct {
	CommonConfidentialResource
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

func (d *ConfidentialResourceBase) FlushState(ctx context.Context, uuid string, data interface{}, resp *resource.CreateResponse) {
	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if trackErr := d.factory.TrackObjectId(ctx, uuid); trackErr != nil {
		errMsg := fmt.Sprintf("could not track the object entered into the state: %s", trackErr.Error())
		tflog.Error(ctx, errMsg)
		resp.Diagnostics.AddError("incomplete object tracking", errMsg)
	}
}
