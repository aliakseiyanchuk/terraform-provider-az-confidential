package apim

import (
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"regexp"
)

type DestinationApiManagement struct {
	AzSubscriptionId types.String `tfsdk:"az_subscription_id"`
	ResourceGroup    types.String `tfsdk:"resource_group"`
	ServiceName      types.String `tfsdk:"api_management_name"`
}

type DestinationSubscriptionCoordinateModel struct {
	DestinationApiManagement
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

var productRegexp = regexp.MustCompile("^/products/(.+)$")
var apisRegexp = regexp.MustCompile("^/apis/(.+)$")

func (d *DestinationSubscriptionCoordinateModel) Accept(props *armapimanagement.SubscriptionContractProperties) {
	if props == nil {
		core.StringToOptionalTerraform("", &d.ProductIdentifier)
		core.StringToOptionalTerraform("", &d.APIIdentifier)
		return
	}

	core.ConvertStingPrtToTerraform(props.OwnerID, &d.UserIdentifier)

	productId := ""
	apiId := ""

	scope := *props.Scope
	if prodMatcher := productRegexp.FindStringSubmatch(scope); prodMatcher != nil {
		productId = prodMatcher[1]
	} else if apiMatcher := apisRegexp.FindStringSubmatch(scope); apiMatcher != nil {
		apiId = apiMatcher[1]
	}

	core.StringToOptionalTerraform(productId, &d.ProductIdentifier)
	core.StringToOptionalTerraform(apiId, &d.APIIdentifier)
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
		return fmt.Sprintf("/products/%s", d.ProductIdentifier.ValueString())
	} else if !d.APIIdentifier.IsNull() {
		return fmt.Sprintf("/apis/%s", d.APIIdentifier.ValueString())
	} else {
		return "/apis"
	}
}
