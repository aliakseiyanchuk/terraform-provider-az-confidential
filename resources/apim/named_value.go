package apim

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
		dest.AzSubscriptionId,
		dest.ResourceGroup,
		dest.ServiceName,
		dest.Name,
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
	// TODO: This code may need checking for nulls and effectively empty settings
	tagSet, _ := core.ConvertToTerraformSet[*string](
		func(s *string) attr.Value { return types.StringValue(*s) },
		types.StringType,
		v.Properties.Tags...,
	)

	mdl.Tags = tagSet
}

type NamedValueSubscriptionSpecializer struct {
	factory core.AZClientsFactory
}

func (n *NamedValueSubscriptionSpecializer) SetFactory(factory core.AZClientsFactory) {
	n.factory = factory
}

func (n *NamedValueSubscriptionSpecializer) NewTerraformModel() NamedValueModel {
	return NamedValueModel{}
}

func (n *NamedValueSubscriptionSpecializer) ConvertToTerraform(azObj armapimanagement.NamedValueContract, tfModel *NamedValueModel) diag.Diagnostics {
	tfModel.Accept(azObj)
	return nil
}

func (n *NamedValueSubscriptionSpecializer) GetConfidentialMaterialFrom(mdl NamedValueModel) resources.ConfidentialMaterialModel {
	return mdl.ConfidentialMaterialModel
}

func (n *NamedValueSubscriptionSpecializer) GetSupportedConfidentialMaterialTypes() []string {
	return []string{"api_management/named_value"}
}

func (n *NamedValueSubscriptionSpecializer) CheckPlacement(ctx context.Context, uuid string, labels []string, tfModel *NamedValueModel) diag.Diagnostics {
	rv := diag.Diagnostics{}
	n.factory.EnsureCanPlaceLabelledObjectAt(ctx,
		uuid,
		labels,
		"api management named value",
		&tfModel.DestinationNamedValue,
		&rv,
	)

	return rv
}

func (n *NamedValueSubscriptionSpecializer) GetJsonDataImporter() core.ObjectJsonImportSupport[core.ConfidentialStringData] {
	return core.NewVersionedStringConfidentialDataHelper()
}

func (n *NamedValueSubscriptionSpecializer) DoCreate(ctx context.Context, data *NamedValueModel, plainData core.ConfidentialStringData) (armapimanagement.NamedValueContract, diag.Diagnostics) {
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
		rv.AddError("Polling for the completion of the operation was not successful", pollErr.Error())
		return armapimanagement.NamedValueContract{}, rv
	}
	return finalResp.NamedValueContract, nil
}

func (n *NamedValueSubscriptionSpecializer) DoDelete(ctx context.Context, data *NamedValueModel) diag.Diagnostics {
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
		rv.AddError("Cannot disable named value", fmt.Sprintf("Request to delete named value %s failed: %s",
			data.DestinationNamedValue.Name.ValueString(),
			delErr.Error(),
		))
	}

	return rv
}

func (n *NamedValueSubscriptionSpecializer) DoRead(ctx context.Context, data *NamedValueModel, plainData core.ConfidentialStringData) (armapimanagement.NamedValueContract, resources.ResourceExistenceCheck, diag.Diagnostics) {
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

	if value.Value != nil && plainData.GetStingData() == *value.Value {
		return resp.NamedValueContract, resources.ResourceExists, nil
	}

	return resp.NamedValueContract, resources.ResourceConfidentialDataDrift, nil
}

func (n *NamedValueSubscriptionSpecializer) DoUpdate(ctx context.Context, data *NamedValueModel, plainData core.ConfidentialStringData) (armapimanagement.NamedValueContract, diag.Diagnostics) {
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
		rv.AddError("Attempt to start create operation was not successful", err.Error())
		return armapimanagement.NamedValueContract{}, rv
	}

	finalResp, pollErr := poller.PollUntilDone(ctx, nil)
	if pollErr != nil {
		rv.AddError("Polling for the completion of the operation was not successful", pollErr.Error())
		return armapimanagement.NamedValueContract{}, rv
	}
	return finalResp.NamedValueContract, nil

}

var namedValueResourceMarkdownDescription string

const NamedValueObjectType = "api management/named value"

func NewNamedValueResource() resource.Resource {
	specificAttrs := map[string]schema.Attribute{
		"destination_named_value": schema.SingleNestedAttribute{
			Required:            true,
			MarkdownDescription: "Destination named value",
			Attributes: map[string]schema.Attribute{
				"vault_name": schema.StringAttribute{
					Optional:    true,
					Description: "Vault where the secret needs to be stored. If omitted, defaults to the vault containing the wrapping key",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"name": schema.StringAttribute{
					Optional:    false,
					Required:    true,
					Description: "Name of the named value",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
			},
		},
	}

	resourceSchema := schema.Schema{
		Description:         "Creates a named value in API Management without revealing its value in state",
		MarkdownDescription: namedValueResourceMarkdownDescription,

		Attributes: resources.WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(specificAttrs),
	}

	namedValueSpecializer := &NamedValueSubscriptionSpecializer{}

	return &resources.ConfidentialGenericResource[NamedValueModel, int, core.ConfidentialStringData, armapimanagement.NamedValueContract]{
		Specializer:    namedValueSpecializer,
		MutableRU:      namedValueSpecializer,
		ResourceName:   NamedValueObjectType,
		ResourceSchema: resourceSchema,
	}
}
