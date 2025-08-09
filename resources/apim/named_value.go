package apim

import (
	"context"
	"crypto/rsa"
	_ "embed"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"regexp"
)

type NamedValueModel struct {
	resources.ConfidentialMaterialModel

	DestinationNamedValue DestinationNamedValueModel `tfsdk:"destination_named_value"`
	Tags                  types.Set                  `tfsdk:"tags"`
	DisplayName           types.String               `tfsdk:"display_name"`
	Secret                types.Bool                 `tfsdk:"secret"`
}

type DestinationNamedValueModel struct {
	DestinationApiManagement
	Name types.String `tfsdk:"name"`
}

func (dest *DestinationNamedValueModel) GetLabel() string {
	return fmt.Sprintf("az-c-label:///subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/namedValues/%s",
		core.StringValueOf(&dest.AzSubscriptionId),
		core.StringValueOf(&dest.ResourceGroup),
		core.StringValueOf(&dest.ServiceName),
		core.StringValueOf(&dest.Name),
	)
}

func GetDestinationNamedValueLabel(azSubscriptionId string, resourceGroupName string, serviceName string, namedValueName string) string {
	mdl := DestinationNamedValueModel{
		DestinationApiManagement: DestinationApiManagement{
			AzSubscriptionId: types.StringValue(azSubscriptionId),
			ResourceGroup:    types.StringValue(resourceGroupName),
			ServiceName:      types.StringValue(serviceName),
		},
		Name: types.StringValue(namedValueName),
	}

	return mdl.GetLabel()
}

func (mdl *NamedValueModel) ToNamedValueContract(ctx context.Context) armapimanagement.NamedValueCreateContract {
	rv := armapimanagement.NamedValueCreateContract{
		Name: mdl.DestinationNamedValue.Name.ValueStringPointer(),
		Properties: &armapimanagement.NamedValueCreateContractProperties{
			DisplayName: mdl.DisplayName.ValueStringPointer(),
			KeyVault:    nil,
			Secret:      mdl.Secret.ValueBoolPointer(),
			Tags:        core.TerraformStringSetAsPtr(ctx, mdl.Tags),
		},
	}
	rv.Name = mdl.DestinationNamedValue.Name.ValueStringPointer()
	rv.Properties.DisplayName = mdl.DisplayName.ValueStringPointer()
	rv.Properties.Secret = mdl.Secret.ValueBoolPointer()

	return rv
}

func (mdl *NamedValueModel) ToUpdateProperties(ctx context.Context) armapimanagement.NamedValueUpdateParameters {
	rv := armapimanagement.NamedValueUpdateParameters{
		Properties: &armapimanagement.NamedValueUpdateParameterProperties{
			DisplayName: mdl.DisplayName.ValueStringPointer(),
			KeyVault:    nil,
			Secret:      mdl.Secret.ValueBoolPointer(),
			Tags:        core.TerraformStringSetAsPtr(ctx, mdl.Tags),
		},
	}

	return rv
}

func (mdl *NamedValueModel) Accept(v armapimanagement.NamedValueContract) {
	if v.ID != nil {
		mdl.Id = types.StringValue(*v.ID)
	}

	core.ConvertStingPrtToTerraform(v.Properties.DisplayName, &mdl.DisplayName)
	core.ConvertBoolPrtToTerraform(v.Properties.Secret, &mdl.Secret)

	// If tags are set in the contract, we'll save these to state. Otherwise,
	// the nil value will be set only if the tag value is not currently known,
	// or the state contains data. This is because an empty tag set is considered
	// to be the same as an nil tag set.
	if v.Properties.Tags != nil && len(v.Properties.Tags) > 0 {
		tagSet, _ := core.ConvertToTerraformSet[*string](
			func(s *string) attr.Value { return types.StringValue(*s) },
			types.StringType,
			v.Properties.Tags...,
		)
		mdl.Tags = tagSet
	} else if mdl.Tags.IsUnknown() || len(v.Properties.Tags) > 0 {
		mdl.Tags = types.SetNull(types.StringType)
	}

}

type NamedValueSpecializer struct {
	factory core.AZClientsFactory
}

func (n *NamedValueSpecializer) SetFactory(factory core.AZClientsFactory) {
	n.factory = factory
}

func (n *NamedValueSpecializer) NewTerraformModel() NamedValueModel {
	return NamedValueModel{}
}

func (n *NamedValueSpecializer) ConvertToTerraform(azObj armapimanagement.NamedValueContract, tfModel *NamedValueModel) diag.Diagnostics {
	tfModel.Accept(azObj)
	return nil
}

func (n *NamedValueSpecializer) GetConfidentialMaterialFrom(mdl NamedValueModel) resources.ConfidentialMaterialModel {
	return mdl.ConfidentialMaterialModel
}

func (n *NamedValueSpecializer) Decrypt(_ context.Context, em core.EncryptedMessage, decr core.RSADecrypter) (core.ConfidentialDataJsonHeader, core.ConfidentialStringData, error) {
	return DecryptNamedValueMessage(em, decr)
}

func (n *NamedValueSpecializer) CheckPlacement(ctx context.Context, pc []core.ProviderConstraint, pl []core.PlacementConstraint, tfModel *NamedValueModel) diag.Diagnostics {
	rv := diag.Diagnostics{}
	n.factory.EnsureCanPlaceLabelledObjectAt(ctx,
		pc,
		pl,
		"api management named value",
		&tfModel.DestinationNamedValue,
		&rv,
	)

	return rv
}

func (n *NamedValueSpecializer) GetJsonDataImporter() core.ObjectJsonImportSupport[core.ConfidentialStringData] {
	return core.NewVersionedStringConfidentialDataHelper(NamedValueObjectType)
}

func (n *NamedValueSpecializer) DoCreate(ctx context.Context, data *NamedValueModel, plainData core.ConfidentialStringData) (armapimanagement.NamedValueContract, diag.Diagnostics) {
	rv := diag.Diagnostics{}

	if data.DisplayName.IsNull() || data.DisplayName.IsUnknown() {
		data.DisplayName = types.StringValue(data.DestinationNamedValue.Name.ValueString())
	}

	subscriptionId := data.DestinationNamedValue.AzSubscriptionId.ValueString()
	namedValueClient, err := n.factory.GetApimNamedValueClient(subscriptionId)
	if err != nil {
		rv.AddError("Cannot acquire API management named value client", fmt.Sprintf("Cannot acquire API management client to this subscription %s: %s", subscriptionId, err.Error()))
		return armapimanagement.NamedValueContract{}, rv
	} else if namedValueClient == nil {
		rv.AddError("Cannot acquire API management named value client", "API management client returned is nil")
		return armapimanagement.NamedValueContract{}, rv
	}

	params := data.ToNamedValueContract(ctx)
	params.Properties.Value = to.Ptr(plainData.GetStingData())

	poller, err := namedValueClient.BeginCreateOrUpdate(ctx,
		data.DestinationNamedValue.ResourceGroup.ValueString(),
		data.DestinationNamedValue.ServiceName.ValueString(),
		data.DestinationNamedValue.Name.ValueString(),
		params,
		nil,
	)

	if err != nil {
		rv.AddError("Attempt to start create operation was not successful", err.Error())
		return armapimanagement.NamedValueContract{}, rv
	}

	finalResp, pollErr := poller.PollUntilDone(ctx, nil)
	if pollErr != nil {
		rv.AddError("Polling for the completion of the create operation was not successful", pollErr.Error())
		return armapimanagement.NamedValueContract{}, rv
	}
	return finalResp.NamedValueContract, nil
}

func (n *NamedValueSpecializer) DoDelete(ctx context.Context, data *NamedValueModel) diag.Diagnostics {
	rv := diag.Diagnostics{}

	subscriptionId := data.DestinationNamedValue.AzSubscriptionId.ValueString()
	namedValueClient, err := n.factory.GetApimNamedValueClient(subscriptionId)
	if err != nil {
		rv.AddError("Cannot acquire API management named value client", fmt.Sprintf("Cannot acquire API management client to this subscription %s: %s", subscriptionId, err.Error()))
		return rv
	} else if namedValueClient == nil {
		rv.AddError("Cannot acquire API management named value client", "API management client returned is nil")
		return rv
	}

	_, delErr := namedValueClient.Delete(ctx,
		data.DestinationNamedValue.ResourceGroup.ValueString(),
		data.DestinationNamedValue.ServiceName.ValueString(),
		data.DestinationNamedValue.Name.ValueString(),
		"*",
		nil,
	)

	if delErr != nil {
		rv.AddError("Cannot delete named value", fmt.Sprintf("Request to delete named value %s failed: %s",
			data.DestinationNamedValue.Name.ValueString(),
			delErr.Error(),
		))
	}

	return rv
}

func (n *NamedValueSpecializer) DoRead(ctx context.Context, data *NamedValueModel, plainData core.ConfidentialStringData) (armapimanagement.NamedValueContract, resources.ResourceExistenceCheck, diag.Diagnostics) {
	rv := diag.Diagnostics{}

	// The key version was never created; nothing needs to be read here.
	if data.Id.IsUnknown() {
		return armapimanagement.NamedValueContract{}, resources.ResourceNotYetCreated, rv

	}

	subscriptionId := data.DestinationNamedValue.AzSubscriptionId.ValueString()
	namedValueClient, err := n.factory.GetApimNamedValueClient(subscriptionId)
	if err != nil {
		rv.AddError("Cannot acquire API management named value client", fmt.Sprintf("Cannot acquire API management client to this subscription %s: %s", subscriptionId, err.Error()))
		return armapimanagement.NamedValueContract{}, resources.ResourceCheckError, rv
	} else if namedValueClient == nil {
		rv.AddError("Cannot acquire API management named value client", "API management client returned is nil")
		return armapimanagement.NamedValueContract{}, resources.ResourceCheckError, rv
	}

	resp, err := namedValueClient.Get(ctx,
		data.DestinationNamedValue.ResourceGroup.ValueString(),
		data.DestinationNamedValue.ServiceName.ValueString(),
		data.DestinationNamedValue.Name.ValueString(),
		nil,
	)

	if err != nil {
		if core.IsResourceNotFoundError(err) {
			if n.factory.IsObjectTrackingEnabled() {
				rv.AddWarning(
					"Named value removed from API management",
					fmt.Sprintf("Named value %s is no longer in API Management sertvice %s in group %s. The provider tracks confidential objects; creating this named value again will be rejected as duplicate. If creathing this named value again is intentional, re-encrypt ciphertext.",
						data.DestinationNamedValue.Name.ValueString(),
						data.DestinationNamedValue.ServiceName.ValueString(),
						data.DestinationNamedValue.ResourceGroup.ValueString(),
					),
				)
			}

			return armapimanagement.NamedValueContract{}, resources.ResourceNotFound, rv
		} else {
			rv.AddError("Cannot read name value", fmt.Sprintf("Cannot read mamed value %s in API Management sertvice %s in group %s: %s",
				data.DestinationNamedValue.Name.ValueString(),
				data.DestinationNamedValue.ServiceName.ValueString(),
				data.DestinationNamedValue.ResourceGroup.ValueString(),
				err.Error()))
			return armapimanagement.NamedValueContract{}, resources.ResourceCheckError, rv
		}
	}

	value, valueErr := namedValueClient.ListValue(
		ctx,
		data.DestinationNamedValue.ResourceGroup.ValueString(),
		data.DestinationNamedValue.ServiceName.ValueString(),
		data.DestinationNamedValue.Name.ValueString(),
		nil,
	)

	if valueErr != nil {
		rv.AddError("Cannot read named value content", valueErr.Error())
		return armapimanagement.NamedValueContract{}, resources.ResourceCheckError, rv
	}

	tflog.Info(ctx, fmt.Sprintf("Detecting drift: want=%s, have=%s", plainData.GetStingData(), *value.Value))

	if value.Value != nil && plainData.GetStingData() == *value.Value {
		return resp.NamedValueContract, resources.ResourceExists, nil
	}

	tflog.Warn(ctx, "Detected a drift in the confidential material")

	return resp.NamedValueContract, resources.ResourceConfidentialDataDrift, nil
}

func (n *NamedValueSpecializer) SetDriftToConfidentialData(_ context.Context, planData *NamedValueModel) {
	planData.ConfidentialMaterialModel.EncryptedSecret = types.StringValue(resources.CreateDriftMessage("named value"))
}

func (n *NamedValueSpecializer) DoUpdate(ctx context.Context, data *NamedValueModel, plainData core.ConfidentialStringData) (armapimanagement.NamedValueContract, diag.Diagnostics) {
	rv := diag.Diagnostics{}

	subscriptionId := data.DestinationNamedValue.AzSubscriptionId.ValueString()
	namedValueClient, err := n.factory.GetApimNamedValueClient(subscriptionId)
	if err != nil {
		rv.AddError("Cannot acquire API management named value client", fmt.Sprintf("Cannot acquire API management client to this subscription %s: %s", subscriptionId, err.Error()))
		return armapimanagement.NamedValueContract{}, rv
	} else if namedValueClient == nil {
		rv.AddError("Cannot acquire API management named value client", "API management client returned is nil")
		return armapimanagement.NamedValueContract{}, rv
	}

	params := data.ToUpdateProperties(ctx)
	params.Properties.Value = to.Ptr(plainData.GetStingData())

	poller, err := namedValueClient.BeginUpdate(ctx,
		data.DestinationNamedValue.ResourceGroup.ValueString(),
		data.DestinationNamedValue.ServiceName.ValueString(),
		data.DestinationNamedValue.Name.ValueString(),
		"*",
		params,
		nil,
	)

	if err != nil {
		rv.AddError("Attempt to start create update operation was not successful", err.Error())
		return armapimanagement.NamedValueContract{}, rv
	}

	finalResp, pollErr := poller.PollUntilDone(ctx, nil)
	if pollErr != nil {
		rv.AddError("Polling for the completion of the operation was not successful", pollErr.Error())
		return armapimanagement.NamedValueContract{}, rv
	}
	return finalResp.NamedValueContract, nil

}

//go:embed named_value.md
var namedValueResourceMarkdownDescription string

const NamedValueObjectType = "api management/named value"

func NewNamedValueResource() resource.Resource {
	displayNameRegexp := regexp.MustCompile("^[a-zA-Z0-9\\.\\-_]+$")

	specificAttrs := map[string]schema.Attribute{
		"display_name": schema.StringAttribute{
			Required:    false,
			Optional:    true,
			Computed:    true,
			Description: "Display name of this named value",
			Validators: []validator.String{
				stringvalidator.RegexMatches(displayNameRegexp, "NamedValue (display name) may contain only letters, digits, periods, dashes and underscores"),
			},
		},
		"secret": schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(true),
			Description: "Whether this named value should be masked in the display in Azure portal",
		},
		"tags": schema.SetAttribute{
			Optional:    true,
			Description: "Tags to place on this named value",
			ElementType: types.StringType,
		},
		"destination_named_value": schema.SingleNestedAttribute{
			Required:            true,
			MarkdownDescription: "Destination named value",
			Attributes: map[string]schema.Attribute{
				"az_subscription_id": schema.StringAttribute{
					Required:    true,
					Description: "Azure subscription of the target APIM service",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"resource_group": schema.StringAttribute{
					Required:    true,
					Description: "Resource group of the target APIM service",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"api_management_name": schema.StringAttribute{
					Required:    true,
					Description: "API Management service name",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"name": schema.StringAttribute{
					Optional:    false,
					Required:    true,
					Description: "Name of the named value to be created",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
					Validators: []validator.String{
						stringvalidator.RegexMatches(displayNameRegexp, "NamedValue may contain only letters, digits, periods, dashes and underscores"),
					},
				},
			},
		},
	}

	resourceSchema := schema.Schema{
		MarkdownDescription: namedValueResourceMarkdownDescription,

		Attributes: resources.WrappedConfidentialMaterialModelSchema(specificAttrs, false),
	}

	namedValueSpecializer := &NamedValueSpecializer{}

	return &resources.ConfidentialGenericResource[NamedValueModel, int, core.ConfidentialStringData, armapimanagement.NamedValueContract]{
		Specializer:    namedValueSpecializer,
		MutableRU:      namedValueSpecializer,
		ResourceName:   "apim_named_value",
		ResourceSchema: resourceSchema,
	}
}

type NamedValueDestinationFunctionParmaValidator struct{}

func (n *NamedValueDestinationFunctionParmaValidator) ValidateParameterObject(ctx context.Context, req function.ObjectParameterValidatorRequest, res *function.ObjectParameterValidatorResponse) {

	if req.Value.IsUnknown() || req.Value.IsNull() {
		return
	}

	v := DestinationNamedValueModel{}

	dg := req.Value.As(ctx, &v, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})
	if dg.HasError() {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Mismatching data structure. This is an internal error of this provider. Please report this issue"))
		return
	}

	if len(v.AzSubscriptionId.ValueString()) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Azure subscription Id is required to lock the named value destination"))
		return
	}

	if len(v.ResourceGroup.ValueString()) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Resource group name is required to lock the named value destination"))
		return
	}

	if len(v.ServiceName.ValueString()) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("API management service name is required to lock the named value destination"))
		return
	}

	if len(v.Name.ValueString()) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Named value name is required to lock the named value destination"))
		return
	}
}

func CreateNamedValueEncryptedMessage(confidentialModel string, dest *DestinationNamedValueModel, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, core.SecondaryProtectionParameters, error) {
	helper := core.NewVersionedStringConfidentialDataHelper(NamedValueObjectType)

	if dest != nil {
		md.PlacementConstraints = []core.PlacementConstraint{core.PlacementConstraint(dest.GetLabel())}
	}

	helper.CreateConfidentialStringData(confidentialModel, md)
	em, emErr := helper.ToEncryptedMessage(pubKey)
	return em, md, emErr
}

func DecryptNamedValueMessage(em core.EncryptedMessage, decrypted core.RSADecrypter) (core.ConfidentialDataJsonHeader, core.ConfidentialStringData, error) {
	helper := core.NewVersionedStringConfidentialDataHelper(NamedValueObjectType)

	err := helper.FromEncryptedMessage(em, decrypted)
	return helper.Header, helper.KnowValue, err
}

func NewNamedValueEncryptorFunction() function.Function {
	rv := resources.FunctionTemplate[string, resources.ResourceProtectionParams, DestinationNamedValueModel]{
		Name:                "encrypt_apim_named_value",
		Summary:             "Produces a ciphertext string suitable for use with az-confidential_apim_named_value resource",
		MarkdownDescription: "Encrypts an APIM named value without the use of the `tfgen` tool",

		DataParameter: function.StringParameter{
			Name:               "named_value",
			Description:        "named value that should be added to the API Management Service",
			AllowNullValue:     false,
			AllowUnknownValues: false,
		},
		ProtectionParameterSupplier: func() resources.ResourceProtectionParams { return resources.ResourceProtectionParams{} },
		DestinationParameter: function.ObjectParameter{
			Name:               "destination_named_value",
			Description:        "Destination vault and secret name",
			AllowNullValue:     true,
			AllowUnknownValues: true,

			AttributeTypes: map[string]attr.Type{
				"az_subscription_id":  types.StringType,
				"resource_group":      types.StringType,
				"api_management_name": types.StringType,
				"name":                types.StringType,
			},

			Validators: []function.ObjectParameterValidator{
				&NamedValueDestinationFunctionParmaValidator{},
			},
		},
		ConfidentialModelSupplier: func() string { return "" },
		DestinationModelSupplier: func() *DestinationNamedValueModel {
			var ptr *DestinationNamedValueModel
			return ptr
		},

		CreatEncryptedMessage: func(confidentialModel string, dest *DestinationNamedValueModel, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, error) {
			em, _, err := CreateNamedValueEncryptedMessage(confidentialModel, dest, md, pubKey)
			return em, err
		},
	}

	return &rv
}
