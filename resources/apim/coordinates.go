package apim

import (
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type DestinationApiManagement struct {
	AzSubscriptionId types.String `tfsdk:"subscription_id"`
	ResourceGroup    types.String `tfsdk:"resource_group"`
	ServiceName      types.String `tfsdk:"api_management_name"`
}

type DestinationSubscriptionCoordinateModel struct {
	DestinationApiManagement
	DisplayName       types.String `tfsdk:"display_name"`
	SubscriptionId    types.String `tfsdk:"apim_subscription_id"`
	APIIdentifier     types.String `tfsdk:"api_id"`
	ProductIdentifier types.String `tfsdk:"product_id"`
	UserIdentifier    types.String `tfsdk:"user_id"`
}

func (d *DestinationSubscriptionCoordinateModel) GetLabel() string {
	return fmt.Sprintf("az-c-label:///subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/subscriptions/%s?api=%s/product=%s/user=%s;",
		d.AzSubscriptionId,
		d.ResourceGroup,
		d.ServiceName,
		d.SubscriptionId,
		d.APIIdentifier,
		d.ProductIdentifier,
		d.UserIdentifier)
}

func (d *DestinationSubscriptionCoordinateModel) Accept(props armapimanagement.SubscriptionContractProperties) {
	core.ConvertStingPrtToTerraform(props.OwnerID, &d.UserIdentifier)
	core.ConvertStingPrtToTerraform(props.Scope, &d.APIIdentifier)
}

func (d *DestinationSubscriptionCoordinateModel) OwnerIdAsPtr() *string {
	if d.UserIdentifier.IsUnknown() || d.UserIdentifier.IsNull() || len(d.UserIdentifier.ValueString()) == 0 {
		return nil
	}

	v := d.UserIdentifier.ValueString()
	return &v
}

func (d *DestinationSubscriptionCoordinateModel) GetScope() string {
	if !d.ProductIdentifier.IsNull() {
		return d.ProductIdentifier.String()
	} else if !d.APIIdentifier.IsNull() {
		return d.APIIdentifier.String()
	} else {
		return "/apis"
	}
}
