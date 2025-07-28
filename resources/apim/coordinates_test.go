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
