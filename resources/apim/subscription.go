package apim

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

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

func (vcd *ConfidentialSubscriptionHelper) CreateSubscriptionData(primary, secondary, objectType string, labels []string) core.VersionedConfidentialData[ConfidentialSubscriptionData] {
	rv := ConfidentialSubscriptionStruct{
		PrimaryKey:   primary,
		SecondaryKey: secondary,
	}

	return vcd.Set(&rv, objectType, labels)
}

func NewConfidentialNamedDataHelper() *ConfidentialSubscriptionHelper {
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

	return rv
}

type SubscriptionModel struct {
	resources.ConfidentialMaterialModel

	DestinationSubscription DestinationSubscriptionCoordinateModel `tfsdk:"destination_subscription"`
	State                   types.String                           `tfsdk:"state"`
	SubscriptionId          types.String                           `tfsdk:"subscription_id"`
	AllowTracing            types.Bool                             `tfsdk:"allow_tracing"`
}

func (sm *SubscriptionModel) ToCreateOrUpdateOptions() armapimanagement.SubscriptionCreateParameters {
	if sm.State.IsUnknown() || sm.State.IsNull() {
		sm.State = types.StringValue("submitted")
	}
	rv := armapimanagement.SubscriptionCreateParameters{
		Properties: &armapimanagement.SubscriptionCreateParameterProperties{
			DisplayName:  to.Ptr(sm.DestinationSubscription.DisplayName.ValueString()),
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
	} else {
		sm.State = types.StringNull()
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

func (s *SubscriptionSpecializer) GetSupportedConfidentialMaterialTypes() []string {
	return []string{"api_management/subscription"}
}

func (s *SubscriptionSpecializer) CheckPlacement(ctx context.Context, uuid string, labels []string, tfModel *SubscriptionModel) diag.Diagnostics {
	rv := diag.Diagnostics{}
	s.factory.EnsureCanPlaceLabelledObjectAt(ctx,
		uuid,
		labels,
		"api management subscription",
		&tfModel.DestinationSubscription,
		&rv,
	)

	return rv
}

func (s *SubscriptionSpecializer) GetJsonDataImporter() core.ObjectJsonImportSupport[ConfidentialSubscriptionData] {
	return NewConfidentialNamedDataHelper()
}

func (s *SubscriptionSpecializer) DoRead(ctx context.Context, planData *SubscriptionModel, plainData ConfidentialSubscriptionData) (armapimanagement.SubscriptionContract, resources.ResourceExistenceCheck, diag.Diagnostics) {
	rv := diag.Diagnostics{}
	if planData.Id.IsUnknown() {
		return armapimanagement.SubscriptionContract{}, resources.ResourceNotYetCreated, nil
	}

	subscriptionId := planData.DestinationSubscription.SubscriptionId.ValueString()
	subscriptionClient, err := s.factory.GetApimSubscriptionClient(subscriptionId)
	if err != nil {
		rv.AddError("Cannot acquire keys client", fmt.Sprintf("Cannot acquire apim subscription client to subscription %s: %s", subscriptionId, err.Error()))
		return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
	} else if subscriptionClient == nil {
		rv.AddError("Cannot acquire keys client", "Keys client returned is nil")
		return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
	}

	var cc = armapimanagement.SubscriptionClient{}

	resourceGroup := planData.DestinationSubscription.ResourceGroup.ValueString()
	apimServiceName := planData.DestinationSubscription.ServiceName.ValueString()
	subscriptionId = planData.SubscriptionId.ValueString()

	subscriptionState, err := subscriptionClient.Get(
		ctx,
		resourceGroup,
		apimServiceName,
		subscriptionId,
		nil)
	if err != nil {
		if core.IsResourceNotFoundError(err) {
			if s.factory.IsObjectTrackingEnabled() {
				rv.AddWarning(
					"Key removed from key vault",
					fmt.Sprintf("Subscripion %s is no longer availble in APIM service in resource group %s API management service %s. The provider tracks confidential objects; creating this API management subscription again will be rejected as duplicate. If creathing this API management subscription again is intentional, re-encrypt ciphertext.",
						subscriptionId,
						resourceGroup,
						apimServiceName,
					),
				)
			}

			return armapimanagement.SubscriptionContract{}, resources.ResourceNotFound, rv
		} else {
			rv.AddError("Cannot read subscription", fmt.Sprintf("Cannot read subscription %s of service %s in resource group %s: %s",
				subscriptionId,
				apimServiceName,
				resourceGroup,
				err.Error()))
			return armapimanagement.SubscriptionContract{}, resources.ResourceCheckError, rv
		}
	}

	keys, keyReadErr := cc.ListSecrets(ctx, resourceGroup, apimServiceName, subscriptionId, nil)
	if keyReadErr != nil {
		rv.AddError("Cannot read subscription keys", fmt.Sprintf("Cannot read subscription keys %s of service %s in resource group %s: %s",
			subscriptionId,
			apimServiceName,
			resourceGroup,
			keyReadErr.Error()))
		return subscriptionState.SubscriptionContract, resources.ResourceCheckError, rv
	}

	// Catch and detect the drift.
	if plainData.GetPrimaryKey() != *keys.PrimaryKey || plainData.GetSecondaryKey() != *keys.SecondaryKey {
		//planData.ConfidentialMaterialModel.Hash(*keys.PrimaryKey, *keys.SecondaryKey)

		rv.AddWarning("Subscription keys have drifted",
			fmt.Sprintf("API management subscription %s of service %s in resource group %s does not match the state specified in ciphertext",
				subscriptionId,
				apimServiceName,
				resourceGroup),
		)

		return subscriptionState.SubscriptionContract, resources.ResourceConfidentialDataDrift, rv
	}

	return subscriptionState.SubscriptionContract, resources.ResourceExists, rv
}

func (s *SubscriptionSpecializer) DoCreate(ctx context.Context, planData *SubscriptionModel, plainData ConfidentialSubscriptionData) (armapimanagement.SubscriptionContract, diag.Diagnostics) {
	rvDiag := diag.Diagnostics{}

	subscriptionClient, secErr := s.factory.GetApimSubscriptionClient(planData.DestinationSubscription.AzSubscriptionId.ValueString())
	if secErr != nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", secErr.Error())
		return armapimanagement.SubscriptionContract{}, rvDiag
	} else if subscriptionClient == nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", "Nil client returned while no error was raised. This is a provider bug. Please report this")
		return armapimanagement.SubscriptionContract{}, rvDiag
	}

	//var cc armapimanagement.SubscriptionClient
	//cc.CreateOrUpdate()

	createOpts := planData.ToCreateOrUpdateOptions()
	createOpts.Properties.PrimaryKey = to.Ptr(plainData.GetPrimaryKey())
	createOpts.Properties.SecondaryKey = to.Ptr(plainData.GetSecondaryKey())

	if !planData.DestinationSubscription.SubscriptionId.IsUnknown() && !planData.DestinationSubscription.SubscriptionId.IsNull() && len(planData.DestinationSubscription.SubscriptionId.ValueString()) > 0 {
		planData.SubscriptionId = types.StringValue(planData.DestinationSubscription.SubscriptionId.ValueString())
	} else {
		planData.SubscriptionId = types.StringValue(uuid.New().String())
	}

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

func (s *SubscriptionSpecializer) DoUpdate(ctx context.Context, planData *SubscriptionModel, lainData ConfidentialSubscriptionData) (armapimanagement.SubscriptionContract, diag.Diagnostics) {
	//TODO implement me
	panic("implement me")
}

func (s *SubscriptionSpecializer) DoDelete(ctx context.Context, planData *SubscriptionModel) diag.Diagnostics {
	rvDiag := diag.Diagnostics{}

	subscriptionClient, secErr := s.factory.GetApimSubscriptionClient(planData.DestinationSubscription.AzSubscriptionId.ValueString())
	if secErr != nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", secErr.Error())
		return rvDiag
	} else if subscriptionClient == nil {
		rvDiag.AddError("APIM subscription client cannot be retrieved", "Nil client returned while no error was raised. This is a provider bug. Please report this")
		return rvDiag
	}

	_, err := subscriptionClient.Delete(ctx,
		planData.DestinationSubscription.ResourceGroup.ValueString(),
		planData.DestinationSubscription.ServiceName.ValueString(),
		planData.SubscriptionId.ValueString(),
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

func NewConfidentialSubscriptionResource() resource.Resource {
	modelAttributes := map[string]schema.Attribute{
		"destination_subscription": schema.SingleNestedAttribute{
			Required:            true,
			MarkdownDescription: "Defines the APIM subscription to be created",
			Attributes: map[string]schema.Attribute{
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
		Description:         "Creates a secret in Azure KeyVault without revealing its value in state",
		MarkdownDescription: subscriptionResourceMarkdownDescription,

		Attributes: resources.WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(modelAttributes),
	}

	apimSubscriptionSpecializer := &SubscriptionSpecializer{}

	return &resources.ConfidentialGenericResource[SubscriptionModel, int, ConfidentialSubscriptionData, armapimanagement.SubscriptionContract]{
		Specializer:    apimSubscriptionSpecializer,
		MutableRU:      apimSubscriptionSpecializer,
		ResourceName:   "secret",
		ResourceSchema: resourceSchema,
	}
}
