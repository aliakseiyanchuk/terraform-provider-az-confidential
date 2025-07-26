package apim

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"regexp"
)

func GetDestinationSubscriptionLabel(azSubscriptionId,
	resourceGroupName, serviceName, subscriptionId, apiScope, productScope, owner string) string {
	mdl := DestinationSubscriptionCoordinateModel{
		DestinationApiManagement: DestinationApiManagement{
			AzSubscriptionId: types.StringValue(azSubscriptionId),
			ResourceGroup:    types.StringValue(resourceGroupName),
			ServiceName:      types.StringValue(serviceName),
		},
		SubscriptionId:    types.StringValue(subscriptionId),
		APIIdentifier:     types.StringValue(apiScope),
		ProductIdentifier: types.StringValue(productScope),
		UserIdentifier:    types.StringValue(owner),
	}

	return mdl.GetLabel()
}

type ConfidentialSubscriptionData interface {
	GetPrimaryKey() string
	GetSecondaryKey() string
}
type ConfidentialSubscriptionStruct struct {
	PrimaryKey   string `json:"pk"`
	SecondaryKey string `json:"sk"`
}

func (cnd *ConfidentialSubscriptionStruct) From(c ConfidentialSubscriptionData) {
	cnd.PrimaryKey = c.GetPrimaryKey()
	cnd.SecondaryKey = c.GetSecondaryKey()
}

func (cnd *ConfidentialSubscriptionStruct) Into(c ConfidentialSubscriptionStruct) {
	c.PrimaryKey = cnd.PrimaryKey
	c.SecondaryKey = cnd.SecondaryKey
}

func (cnd *ConfidentialSubscriptionStruct) GetPrimaryKey() string {
	return cnd.PrimaryKey
}

func (cnd *ConfidentialSubscriptionStruct) GetSecondaryKey() string {
	return cnd.SecondaryKey
}

type ConfidentialSubscriptionHelper struct {
	core.VersionedConfidentialDataHelperTemplate[ConfidentialSubscriptionData, ConfidentialSubscriptionStruct]
}

func (vcd *ConfidentialSubscriptionHelper) CreateSubscriptionData(primary, secondary string, md core.VersionedConfidentialMetadata) core.VersionedConfidentialData[ConfidentialSubscriptionData] {
	p := core.VersionedConfidentialDataCreateParam[ConfidentialSubscriptionData]{
		Value: &ConfidentialSubscriptionStruct{
			PrimaryKey:   primary,
			SecondaryKey: secondary,
		},
		VersionedConfidentialMetadata: md,
	}

	return vcd.Set(p)
}

func NewConfidentialSubscriptionHelper() *ConfidentialSubscriptionHelper {
	rv := &ConfidentialSubscriptionHelper{}
	rv.KnowValue = &ConfidentialSubscriptionStruct{}
	rv.ModelName = "api_management/subscription/v1"

	rv.ModelAtRestSupplier = func(s string) (ConfidentialSubscriptionStruct, error) {
		var err error
		if s != "api_management/subscription/v1" {
			err = fmt.Errorf("model %s is not supported", s)
		}
		return ConfidentialSubscriptionStruct{}, err
	}

	rv.ValueToRest = func(data ConfidentialSubscriptionData) ConfidentialSubscriptionStruct {
		rvMdl := ConfidentialSubscriptionStruct{}
		rvMdl.From(data)
		return rvMdl
	}

	rv.RestToValue = func(model ConfidentialSubscriptionStruct) ConfidentialSubscriptionData {
		rvData := &ConfidentialSubscriptionStruct{
			PrimaryKey:   model.GetPrimaryKey(),
			SecondaryKey: model.GetSecondaryKey(),
		}

		return rvData
	}

	return rv
}

type SubscriptionModel struct {
	resources.ConfidentialMaterialModel

	DestinationSubscription DestinationSubscriptionCoordinateModel `tfsdk:"destination_subscription"`
	State                   types.String                           `tfsdk:"state"`
	DisplayName             types.String                           `tfsdk:"display_name"`
	SubscriptionId          types.String                           `tfsdk:"subscription_id"`
	AllowTracing            types.Bool                             `tfsdk:"allow_tracing"`
}

func (sm *SubscriptionModel) ToCreateOrUpdateOptions() armapimanagement.SubscriptionCreateParameters {
	rv := armapimanagement.SubscriptionCreateParameters{
		Properties: &armapimanagement.SubscriptionCreateParameterProperties{
			DisplayName:  to.Ptr(sm.DisplayName.ValueString()),
			Scope:        to.Ptr(sm.DestinationSubscription.GetScope()),
			State:        to.Ptr(armapimanagement.SubscriptionState(sm.State.ValueString())),
			AllowTracing: to.Ptr(sm.AllowTracing.ValueBool()),
			OwnerID:      sm.DestinationSubscription.OwnerIdAsPtr(),
		},
	}

	return rv
}

func (sm *SubscriptionModel) ToUpdateOptions() armapimanagement.SubscriptionUpdateParameters {
	rv := armapimanagement.SubscriptionUpdateParameters{
		Properties: &armapimanagement.SubscriptionUpdateParameterProperties{
			DisplayName:  to.Ptr(sm.DisplayName.ValueString()),
			Scope:        to.Ptr(sm.DestinationSubscription.GetScope()),
			State:        to.Ptr(armapimanagement.SubscriptionState(sm.State.ValueString())),
			AllowTracing: to.Ptr(sm.AllowTracing.ValueBool()),
			OwnerID:      sm.DestinationSubscription.OwnerIdAsPtr(),
		},
	}

	return rv
}

func (sm *SubscriptionModel) Accept(r armapimanagement.SubscriptionContract) {
	core.ConvertStingPrtToTerraform(r.ID, &sm.Id)
	if r.Properties != nil {
		core.ConvertBoolPrtToTerraform(r.Properties.AllowTracing, &sm.AllowTracing)
		core.ConvertStingPrtToTerraform((*string)(r.Properties.State), &sm.State)
		core.ConvertStingPrtToTerraform(r.Properties.DisplayName, &sm.DisplayName)
	} else {
		sm.State = types.StringNull()
		sm.DisplayName = types.StringNull()
		sm.AllowTracing = types.BoolNull()
	}

}

type SubscriptionSpecializer struct {
	factory core.AZClientsFactory
}

func (s *SubscriptionSpecializer) SetFactory(factory core.AZClientsFactory) {
	s.factory = factory
}

func (s *SubscriptionSpecializer) NewTerraformModel() SubscriptionModel {
	return SubscriptionModel{}
}

func (s *SubscriptionSpecializer) ConvertToTerraform(azObj armapimanagement.SubscriptionContract, tfModel *SubscriptionModel) diag.Diagnostics {
	tfModel.Accept(azObj)
	return nil
}

func (s *SubscriptionSpecializer) GetConfidentialMaterialFrom(mdl SubscriptionModel) resources.ConfidentialMaterialModel {
	return mdl.ConfidentialMaterialModel
}

const SubscriptionObjectType = "api management/subscription"

func (s *SubscriptionSpecializer) GetSupportedConfidentialMaterialTypes() []string {
	return []string{SubscriptionObjectType}
}

func (s *SubscriptionSpecializer) CheckPlacement(ctx context.Context, pc []core.ProviderConstraint, pl []core.PlacementConstraint, tfModel *SubscriptionModel) diag.Diagnostics {
	rv := diag.Diagnostics{}
	s.factory.EnsureCanPlaceLabelledObjectAt(ctx,
		pc,
		pl,
		"api management subscription",
		&tfModel.DestinationSubscription,
		&rv,
	)

	return rv
}

func (s *SubscriptionSpecializer) GetJsonDataImporter() core.ObjectJsonImportSupport[ConfidentialSubscriptionData] {
	return NewConfidentialSubscriptionHelper()
}

var idExp = regexp.MustCompile("/subscriptions/(.*)/resourceGroups/(.*)/providers/Microsoft.ApiManagement/service/(.*)/subscriptions/(.*)")

func (s *SubscriptionSpecializer) DoRead(ctx context.Context, planData *SubscriptionModel, plainData ConfidentialSubscriptionData) (armapimanagement.SubscriptionContract, resources.ResourceExistenceCheck, diag.Diagnostics) {
	rv := diag.Diagnostics{}
	if planData.Id.IsUnknown() {
		return armapimanagement.SubscriptionContract{}, resources.ResourceNotYetCreated, nil
	}

	azSubscriptionId, azErr := s.factory.GetAzSubscription(planData.DestinationSubscription.AzSubscriptionId.ValueString())
	if azErr != nil {
		rv.AddError(
			"Missing Azure subscription Id",
			"Creating Azure objects requires identifying a subscription; either on the level of the provider, or on the level of the resource")
		return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
	}

	matcher := idExp.FindStringSubmatch(planData.Id.ValueString())
	if matcher == nil {
		rv.AddError("Resource identifier is malformed", fmt.Sprintf("The id of this resource (%s) does not match the expected format. This is a bug of the provider. Please report this", planData.Id.ValueString()))
		return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
	}
	azSubscriptionIdFromId := matcher[1]
	resourceGroup := matcher[2]
	apimServiceName := matcher[3]
	apimSubscriptionIdFromId := matcher[4]

	if azSubscriptionIdFromId != azSubscriptionId {
		rv.AddError(
			"Implicit move",
			fmt.Sprintf("This APIM subscription is created in Azure subscription %s, whereas the configuration now requires it to be created in Azure subscription %s. Delete and recreate this resource", azSubscriptionIdFromId, azSubscriptionId),
		)
		return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
	}

	subscriptionClient, err := s.factory.GetApimSubscriptionClient(azSubscriptionIdFromId)
	if err != nil {
		rv.AddError("Cannot acquire APIM subscription client", fmt.Sprintf("Cannot acquire apim subscription client to subscription %s: %s", azSubscriptionIdFromId, err.Error()))
		return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
	} else if subscriptionClient == nil {
		rv.AddError("Cannot acquire APIM subscription client", "Keys client returned is nil")
		return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
	}

	subscriptionState, err := subscriptionClient.Get(
		ctx,
		resourceGroup,
		apimServiceName,
		apimSubscriptionIdFromId,
		nil)
	if err != nil {
		if core.IsResourceNotFoundError(err) {
			if s.factory.IsObjectTrackingEnabled() {
				rv.AddWarning(
					"Subscription removed from API management",
					fmt.Sprintf("Subscripion %s is no longer availble in APIM service in resource group %s API management service %s. The provider tracks confidential objects; creating this API management subscription again will be rejected as duplicate. If creathing this API management subscription again is intentional, re-encrypt ciphertext.",
						apimSubscriptionIdFromId,
						resourceGroup,
						apimServiceName,
					),
				)
			}

			return armapimanagement.SubscriptionContract{}, resources.ResourceNotFound, rv
		} else {
			rv.AddError("Cannot read subscription", fmt.Sprintf("Cannot read subscription %s of service %s in resource group %s: %s",
				apimSubscriptionIdFromId,
				apimServiceName,
				resourceGroup,
				err.Error()))
			return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
		}
	}

	keys, keyReadErr := subscriptionClient.ListSecrets(ctx, resourceGroup, apimServiceName, apimSubscriptionIdFromId, nil)
	if keyReadErr != nil {
		rv.AddError("Cannot read subscription keys", fmt.Sprintf("Cannot read subscription keys %s of service %s in resource group %s: %s",
			apimSubscriptionIdFromId,
			apimServiceName,
			resourceGroup,
			keyReadErr.Error()))
		return subscriptionState.SubscriptionContract, resources.ResourceCheckError, rv
	}

	// Catch and detect the drift.
	if plainData.GetPrimaryKey() != *keys.PrimaryKey || plainData.GetSecondaryKey() != *keys.SecondaryKey {
		rv.AddWarning("Subscription keys have drifted from the state declared in ciphertext",
			fmt.Sprintf("API management subscription %s of service %s in resource group %s does not match the state specified in ciphertext",
				apimSubscriptionIdFromId,
				apimServiceName,
				resourceGroup),
		)

		return subscriptionState.SubscriptionContract, resources.ResourceConfidentialDataDrift, rv
	}

	return subscriptionState.SubscriptionContract, resources.ResourceExists, rv
}

func (s *SubscriptionSpecializer) SetDriftToConfidentialData(_ context.Context, planData *SubscriptionModel) {
	planData.EncryptedSecret = types.StringValue(resources.CreateDriftMessage("subscription"))
}

func (s *SubscriptionSpecializer) DoCreate(ctx context.Context, planData *SubscriptionModel, plainData ConfidentialSubscriptionData) (armapimanagement.SubscriptionContract, diag.Diagnostics) {
	rvDiag := diag.Diagnostics{}

	azSubscriptionId, azErr := s.factory.GetAzSubscription(planData.DestinationSubscription.AzSubscriptionId.ValueString())
	if azErr != nil {
		rvDiag.AddError(
			"Missing Azure subscription Id",
			"Creating Azure objects requires identifying a subscription; either on the level of the provider, or on the level of the resource")
		return armapimanagement.SubscriptionContract{}, rvDiag
	}

	subscriptionClient, secErr := s.factory.GetApimSubscriptionClient(azSubscriptionId)
	if secErr != nil {
		rvDiag.AddError("Cannot acquire APIM subscription client", secErr.Error())
		return armapimanagement.SubscriptionContract{}, rvDiag
	} else if subscriptionClient == nil {
		rvDiag.AddError("Cannot acquire APIM subscription client", "Nil client returned while no error was raised. This is a provider bug. Please report this")
		return armapimanagement.SubscriptionContract{}, rvDiag
	}

	if !planData.DestinationSubscription.SubscriptionId.IsUnknown() && !planData.DestinationSubscription.SubscriptionId.IsNull() && len(planData.DestinationSubscription.SubscriptionId.ValueString()) > 0 {
		planData.SubscriptionId = types.StringValue(planData.DestinationSubscription.SubscriptionId.ValueString())
	} else {
		planData.SubscriptionId = types.StringValue(uuid.New().String())
	}

	if planData.DisplayName.IsUnknown() {
		planData.DisplayName = types.StringValue(planData.SubscriptionId.ValueString())
	}

	createOpts := planData.ToCreateOrUpdateOptions()
	createOpts.Properties.PrimaryKey = to.Ptr(plainData.GetPrimaryKey())
	createOpts.Properties.SecondaryKey = to.Ptr(plainData.GetSecondaryKey())

	resp, createErr := subscriptionClient.CreateOrUpdate(ctx,
		planData.DestinationSubscription.ResourceGroup.ValueString(),
		planData.DestinationSubscription.ServiceName.ValueString(),
		planData.SubscriptionId.ValueString(),
		createOpts,
		nil,
	)

	if createErr != nil {
		rvDiag.AddError("Cannot create subscription", createErr.Error())
		return armapimanagement.SubscriptionContract{}, rvDiag
	}

	return resp.SubscriptionContract, rvDiag

}

func (s *SubscriptionSpecializer) DoUpdate(ctx context.Context, planData *SubscriptionModel, plainData ConfidentialSubscriptionData) (armapimanagement.SubscriptionContract, diag.Diagnostics) {
	rvDiag := diag.Diagnostics{}

	matcher := idExp.FindStringSubmatch(planData.Id.ValueString())
	if matcher == nil {
		rvDiag.AddError("Resource identifier is malformed", fmt.Sprintf("The id of this resource (%s) does not match the expected format. This is a bug of the provider. Please report this", planData.Id.ValueString()))
		return armapimanagement.SubscriptionContract{}, rvDiag
	}

	azSubscriptionIdFromId := matcher[1]
	resourceGroup := matcher[2]
	apimServiceName := matcher[3]
	apimSubscriptionIdFromId := matcher[4]

	updateOpts := planData.ToUpdateOptions()
	updateOpts.Properties.PrimaryKey = to.Ptr(plainData.GetPrimaryKey())
	updateOpts.Properties.SecondaryKey = to.Ptr(plainData.GetSecondaryKey())

	subscriptionClient, secErr := s.factory.GetApimSubscriptionClient(azSubscriptionIdFromId)
	if secErr != nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", secErr.Error())
		return armapimanagement.SubscriptionContract{}, rvDiag
	} else if subscriptionClient == nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", "Nil client returned while no error was raised. This is a provider bug. Please report this")
		return armapimanagement.SubscriptionContract{}, rvDiag
	}

	resp, updateErr := subscriptionClient.Update(ctx,
		resourceGroup,
		apimServiceName,
		apimSubscriptionIdFromId,
		"*",
		updateOpts,
		nil,
	)

	if updateErr != nil {
		rvDiag.AddError("Cannot update subscription", updateErr.Error())
		return armapimanagement.SubscriptionContract{}, rvDiag
	} else {
		return resp.SubscriptionContract, rvDiag
	}
}

func (s *SubscriptionSpecializer) DoDelete(ctx context.Context, planData *SubscriptionModel) diag.Diagnostics {
	rvDiag := diag.Diagnostics{}

	matcher := idExp.FindStringSubmatch(planData.Id.ValueString())
	if matcher == nil {
		rvDiag.AddError("Resource identifier is malformed", fmt.Sprintf("The id of this resource (%s) does not match the expected format. This is a bug of the provider. Please report this", planData.Id.ValueString()))
		return rvDiag
	}

	azSubscriptionIdFromId := matcher[1]
	resourceGroup := matcher[2]
	apimServiceName := matcher[3]
	apimSubscriptionIdFromId := matcher[4]

	subscriptionClient, secErr := s.factory.GetApimSubscriptionClient(azSubscriptionIdFromId)
	if secErr != nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", secErr.Error())
		return rvDiag
	} else if subscriptionClient == nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", "Nil client returned while no error was raised. This is a provider bug. Please report this")
		return rvDiag
	}

	_, err := subscriptionClient.Delete(ctx,
		resourceGroup,
		apimServiceName,
		apimSubscriptionIdFromId,
		"*",
		nil,
	)

	if err != nil {
		rvDiag.AddError("Cannot delete API Management subscription",
			fmt.Sprintf("Request to delete API Management subscription %s from service %s in resource group %s has failed: %s",
				planData.SubscriptionId.ValueString(),
				planData.DestinationSubscription.ServiceName.ValueString(),
				planData.DestinationSubscription.ResourceGroup.ValueString(),
				err.Error(),
			))
	}

	return rvDiag
}

// TODO: write and embed a readme
var subscriptionResourceMarkdownDescription string

func NewSubscriptionResource() resource.Resource {
	modelAttributes := map[string]schema.Attribute{
		"subscription_id": schema.StringAttribute{
			Computed:    true,
			Description: "Id of the subscription that actually created. Useful in case where destination_subscription does not set a required Id",
		},
		"state": schema.StringAttribute{
			Computed:    true,
			Optional:    true,
			Description: "Required state of the subscription. Defaults to `active` if unspecified",
			Validators: []validator.String{
				stringvalidator.OneOf(
					"active",
					"cancelled",
					"expired",
					"rejected",
					"submitted",
					"suspended",
				),
			},
			Default: stringdefault.StaticString("active"),
		},
		"display_name": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Display name of this subscription. Defaults to subscription Id if unspecified",
		},
		"allow_tracing": schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Whether to allow the tracing of policy execution for this subscription",
			Default:     booldefault.StaticBool(false),
		},
		"destination_subscription": schema.SingleNestedAttribute{
			Required:            true,
			MarkdownDescription: "Defines the APIM subscription to be created",
			Attributes: map[string]schema.Attribute{
				"az_subscription_id": schema.StringAttribute{
					Optional:    true,
					Description: "Id of this subscription where API Management service id deployed. Required if provider is not configured with a default Azure subscription, or the subscription differs from default",

					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"resource_group": schema.StringAttribute{
					Required:    true,
					Description: "Resource group where APIM service is created",

					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"api_management_name": schema.StringAttribute{
					Required:    true,
					Description: "Resource group where APIM service is created",

					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"apim_subscription_id": schema.StringAttribute{
					Optional:    true,
					Description: "API management subscription Id to use",

					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"api_id": schema.StringAttribute{
					Optional:    true,
					Description: "API for which the subscription needs to be created",

					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"product_id": schema.StringAttribute{
					Optional:    true,
					Description: "Product for which the subscription needs to be created",

					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"user_id": schema.StringAttribute{
					Optional:    true,
					Description: "Product for which the subscription needs to be created",

					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
			},
		},
	}

	resourceSchema := schema.Schema{
		Description:         "Creates a subscription in the Azure API management service with pre-set primary and secondary subscription keys",
		MarkdownDescription: subscriptionResourceMarkdownDescription,

		Attributes: resources.WrappedConfidentialMaterialModelSchema(modelAttributes, false),
	}

	apimSubscriptionSpecializer := &SubscriptionSpecializer{}

	return &resources.ConfidentialGenericResource[SubscriptionModel, int, ConfidentialSubscriptionData, armapimanagement.SubscriptionContract]{
		Specializer:    apimSubscriptionSpecializer,
		MutableRU:      apimSubscriptionSpecializer,
		ResourceName:   "apim_subscription",
		ResourceSchema: resourceSchema,
	}
}

type SubscriptionDataFunctionParameter struct {
	PrimaryKey   types.String `tfsdk:"primary_key"`
	SecondaryKey types.String `tfsdk:"secondary_key"`
}

type SubscriptionDataFunctionParameterValidator struct{}

func (s *SubscriptionDataFunctionParameterValidator) ValidateParameterObject(ctx context.Context, req function.ObjectParameterValidatorRequest, res *function.ObjectParameterValidatorResponse) {
	if req.Value.IsUnknown() || req.Value.IsNull() {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Subscription key data cannot be nil"))
	}

	p := SubscriptionDataFunctionParameter{}
	dg := req.Value.As(ctx, &p, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})

	if dg.HasError() {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Mismatching data structure. This is an internal error of this provider. Please report this issue"))
		return
	}

	pk := p.PrimaryKey.ValueString()
	sk := p.SecondaryKey.ValueString()

	if len(pk) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Primary subscription key is required"))
	} else if len(sk) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Secondary subscription key is required"))
	} else if pk == sk {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Primary and secondary key cannot have the same value"))
	}
}

type SubscriptionDestinationFunctionParmaValidator struct{}

func (n *SubscriptionDestinationFunctionParmaValidator) ValidateParameterObject(ctx context.Context, req function.ObjectParameterValidatorRequest, res *function.ObjectParameterValidatorResponse) {

	if req.Value.IsUnknown() || req.Value.IsNull() {
		return
	}

	v := DestinationSubscriptionCoordinateModel{}

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

	// These are minimal requirements for target locking.
}

func NewSubscriptionEncryptorFunction() function.Function {
	rv := resources.FunctionTemplate[SubscriptionDataFunctionParameter, DestinationSubscriptionCoordinateModel]{
		Name:                "encrypt_apim_subscription",
		Summary:             "Produces a ciphertext string suitable for use with az-confidential_apim_subnscription resource",
		MarkdownDescription: "Encrypts an APIM subscription keys without the use of the `tfgen` tool",

		ObjectType: NamedValueObjectType,
		DataParameter: function.ObjectParameter{
			Name:               "subscription_keys",
			Description:        "Subscription keys that need to be created in the target APIM service",
			AllowNullValue:     false,
			AllowUnknownValues: false,

			AttributeTypes: map[string]attr.Type{
				"primary_key":   types.StringType,
				"secondary_key": types.StringType,
			},

			Validators: []function.ObjectParameterValidator{
				&SubscriptionDataFunctionParameterValidator{},
			},
		},
		DestinationParameter: function.ObjectParameter{
			Name:               "destination_subscription",
			Description:        "Destination API management subscription",
			AllowNullValue:     true,
			AllowUnknownValues: true,

			AttributeTypes: map[string]attr.Type{
				"az_subscription_id":   types.StringType,
				"resource_group":       types.StringType,
				"api_management_name":  types.StringType,
				"apim_subscription_id": types.StringType,
				"api_id":               types.StringType,
				"product_id":           types.StringType,
				"user_id":              types.StringType,
			},

			Validators: []function.ObjectParameterValidator{
				&SubscriptionDestinationFunctionParmaValidator{},
			},
		},
		ConfidentialModelSupplier: func() SubscriptionDataFunctionParameter { return SubscriptionDataFunctionParameter{} },
		DestinationModelSupplier: func() *DestinationSubscriptionCoordinateModel {
			var ptr *DestinationSubscriptionCoordinateModel
			return ptr
		},

		CreatEncryptedMessage: func(confidentialModel SubscriptionDataFunctionParameter, dest *DestinationSubscriptionCoordinateModel, md core.VersionedConfidentialMetadata, pubKey *rsa.PublicKey) (core.EncryptedMessage, error) {
			if dest != nil {
				md.PlacementConstraints = []core.PlacementConstraint{core.PlacementConstraint(dest.GetLabel())}
			}

			helper := NewConfidentialSubscriptionHelper()
			_ = helper.CreateSubscriptionData(
				confidentialModel.PrimaryKey.ValueString(),
				confidentialModel.SecondaryKey.ValueString(),
				md)

			return helper.ToEncryptedMessage(pubKey)
		},
	}

	return &rv
}
