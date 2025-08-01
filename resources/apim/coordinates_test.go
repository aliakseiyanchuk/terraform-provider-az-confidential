package apim

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_SDCM_AcceptSubscriptionContractOverrideByProductId(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringValue("apiId"),
		ProductIdentifier: types.StringValue("productId]"),
	}
	props := armapimanagement.SubscriptionContractProperties{
		Scope: to.Ptr("/products/productId"),
	}

	mdl.Accept(&props)
	assert.Equal(t, "", mdl.APIIdentifier.ValueString())
	assert.Equal(t, "productId", mdl.ProductIdentifier.ValueString())
}

func Test_SDCM_AcceptSubscriptionContractOverrideByApiId(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringValue("apiId"),
		ProductIdentifier: types.StringValue("productId]"),
	}
	props := armapimanagement.SubscriptionContractProperties{
		Scope: to.Ptr("/apis/inboundApiId"),
	}

	mdl.Accept(&props)
	assert.Equal(t, "inboundApiId", mdl.APIIdentifier.ValueString())
	assert.Equal(t, "", mdl.ProductIdentifier.ValueString())
}

func Test_SDCM_AcceptSubscriptionContractOverrideByAllApis(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringValue("apiId"),
		ProductIdentifier: types.StringValue("productId]"),
	}
	props := armapimanagement.SubscriptionContractProperties{
		Scope: to.Ptr("/apis"),
	}

	mdl.Accept(&props)
	assert.Equal(t, "", mdl.APIIdentifier.ValueString())
	assert.Equal(t, "", mdl.ProductIdentifier.ValueString())
}

func Test_SDCM_AcceptSubscriptionContractOnNull(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringValue("apiId"),
		ProductIdentifier: types.StringValue("productId]"),
	}

	mdl.Accept(nil)
	assert.Equal(t, "", mdl.APIIdentifier.ValueString())
	assert.Equal(t, "", mdl.ProductIdentifier.ValueString())
}

func Test_SDCM_AcceptSubscriptionContractOnNullWithUnknownOrNullSource(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringUnknown(),
		ProductIdentifier: types.StringNull(),
	}

	mdl.Accept(nil)
	assert.True(t, mdl.APIIdentifier.IsUnknown())
	assert.True(t, mdl.ProductIdentifier.IsNull())
}

func Test_SDCM_GetLabel(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		DestinationApiManagement: DestinationApiManagement{
			AzSubscriptionId: types.StringValue("azSubId"),
			ResourceGroup:    types.StringValue("rg"),
			ServiceName:      types.StringValue("serviceName"),
		},
		SubscriptionId:    types.StringValue("subId"),
		APIIdentifier:     types.StringUnknown(),
		ProductIdentifier: types.StringNull(),
		UserIdentifier:    types.StringValue("userId"),
	}

	assert.Equal(t, "az-c-label:///subscriptions/azSubId/resourceGroups/rg/providers/Microsoft.ApiManagement/service/serviceName/subscriptions/subId?api=/product=/user=userId", mdl.GetLabel())
}

func Test_SDCM_GetScope_Unspecified(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringUnknown(),
		ProductIdentifier: types.StringNull(),
	}

	assert.Equal(t, "/apis", mdl.GetScope())
}

func Test_SDCM_GetScope_ApiScoped(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringValue("apiId"),
		ProductIdentifier: types.StringNull(),
	}

	assert.Equal(t, "/apis/apiId", mdl.GetScope())
}

func Test_SDCM_GetScope_ProductScoped(t *testing.T) {
	mdl := DestinationSubscriptionCoordinateModel{
		APIIdentifier:     types.StringUnknown(),
		ProductIdentifier: types.StringValue("productId"),
	}

	assert.Equal(t, "/products/productId", mdl.GetScope())
}
