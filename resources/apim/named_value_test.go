package apim

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_GetDestinationNamedValueLabel(t *testing.T) {
	v := GetDestinationNamedValueLabel("sub", "rg", "apim", "nv")
	assert.Equal(t, "az-c-label:///subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim/namedValues/nv", v)
}

func Test_NV_DoRead_WhenNotCreated(t *testing.T) {
	mdl := NamedValueModel{}
	mdl.Id = types.StringUnknown()

	ks := &NamedValueSpecializer{}
	_, state, dg := ks.DoRead(context.Background(), &mdl, nil)
	assert.Equal(t, resources.ResourceNotYetCreated, state)
	assert.False(t, dg.HasError())
}

func givenTypicalNamedValueModel() (NamedValueModel, core.ConfidentialStringData) {
	nvModel := NamedValueModel{
		DestinationNamedValue: DestinationNamedValueModel{
			DestinationApiManagement: DestinationApiManagement{
				AzSubscriptionId: types.StringValue("azSubscriptionId"),
				ResourceGroup:    types.StringValue("resourceGroup"),
				ServiceName:      types.StringValue("apimServiceName"),
			},
			Name: types.StringValue("named-value"),
		},
	}
	nvModel.Id = types.StringValue("/subscriptions/az/....")

	plainData := core.StringConfidentialDataJsonModel{
		StringData: "this is a very sensitive named value",
	}

	return nvModel, &plainData
}

func Test_NV_IfApimClientCannotConnect(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientErrs(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), "unit-test-error")

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_IfApimClientIsNil(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientIsNil(mdl.DestinationNamedValue.AzSubscriptionId.ValueString())

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_ReadingNamedValueErrs(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenGetErrs(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		"unit-test-error",
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot read name value", dg[0].Summary())

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_ReadingNamedValueIfRemoved(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenGetReturnsNotFound(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString())

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenIsObjectTrackingEnabled(false)
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceNotFound, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_ReadingNamedValueIfRemovedWhenTrackignEnabled(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenGetReturnsNotFound(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString())

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenIsObjectTrackingEnabled(true)
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceNotFound, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 1, len(dg))
	assert.Equal(t, "Named value removed from API management", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_ReadingNamedValueIfValueCannotBeListed(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenGetReturnsNotFound(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString())

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenIsObjectTrackingEnabled(true)
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceNotFound, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 1, len(dg))
	assert.Equal(t, "Named value removed from API management", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_ReadMatchingValue(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenGet(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString())
	clMock.GivenListValueReturns(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		to.Ptr(plainData.GetStingData()),
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceExists, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_ReadDriftedValue(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenGet(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString())
	clMock.GivenListValueReturns(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		to.Ptr(plainData.GetStingData()+"..drifted"),
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, plainData)
	assert.Equal(t, resources.ResourceConfidentialDataDrift, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_UpdateIfClientCannotConnect(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientErrs(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), "uni-test-error")

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_UpdateIfClientIsNil(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientIsNil(mdl.DestinationNamedValue.AzSubscriptionId.ValueString())

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_UpdateCannotStart(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenBeginUpdateErrs(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		"unit-test-error",
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Attempt to start create update operation was not successful", dg[0].Summary())

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_UpdatePollerErrs(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	pollerMock := &NamedValuePollerMock[armapimanagement.NamedValueClientUpdateResponse]{}
	pollerMock.GivenPollingErrs(armapimanagement.NamedValueClientUpdateResponse{}, "uni-test-error")

	clMock := &NamedValueClientMock{}
	clMock.GivenBeginUpdate(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		pollerMock,
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Polling for the completion of the operation was not successful", dg[0].Summary())

	pollerMock.AssertExpectations(t)
	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_UpdateSucceeds(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	pollerMock := &NamedValuePollerMock[armapimanagement.NamedValueClientUpdateResponse]{}
	pollerMock.GivenPollingSucceeds(armapimanagement.NamedValueClientUpdateResponse{})

	clMock := &NamedValueClientMock{}
	clMock.GivenBeginUpdate(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		pollerMock,
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, plainData)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	pollerMock.AssertExpectations(t)
	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_DeleteIfClientCannotConnect(t *testing.T) {
	mdl, _ := givenTypicalNamedValueModel()
	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientErrs(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), "unit-test-error")

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_DeleteIfClientIsNil(t *testing.T) {
	mdl, _ := givenTypicalNamedValueModel()
	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientIsNil(mdl.DestinationNamedValue.AzSubscriptionId.ValueString())

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_DeleteIfDeleteOperationErrs(t *testing.T) {
	mdl, _ := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenDeleteErrs(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		"unit-test-error",
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot delete named value", dg[0].Summary())

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_DeleteSucceeds(t *testing.T) {
	mdl, _ := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenDelete(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(mdl.DestinationNamedValue.AzSubscriptionId.ValueString(), clMock)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_CreateIfClientCannotConnect(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientErrs(
		mdl.DestinationNamedValue.AzSubscriptionId.ValueString(),
		"unit-test-error",
	)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_CreateIfClientIsNil(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClientIsNil(
		mdl.DestinationNamedValue.AzSubscriptionId.ValueString(),
	)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire API management named value client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_NV_CreateIfBeginCreateOrUpdateErrs(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	clMock := &NamedValueClientMock{}
	clMock.GivenBeginCreateOrUpdateErrs(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		"unit-test-error",
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(
		mdl.DestinationNamedValue.AzSubscriptionId.ValueString(),
		clMock,
	)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Attempt to start create operation was not successful", dg[0].Summary())

	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_CreateIfBeginCreateOrUpdatePollingErrs(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	pollerMock := &NamedValuePollerMock[armapimanagement.NamedValueClientCreateOrUpdateResponse]{}
	pollerMock.GivenPollingErrs(armapimanagement.NamedValueClientCreateOrUpdateResponse{}, "unit-test-error")

	clMock := &NamedValueClientMock{}
	clMock.GivenBeginCreateOrUpdate(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		pollerMock,
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(
		mdl.DestinationNamedValue.AzSubscriptionId.ValueString(),
		clMock,
	)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, plainData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Polling for the completion of the create operation was not successful", dg[0].Summary())

	pollerMock.AssertExpectations(t)
	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_CreateSucceeds(t *testing.T) {
	mdl, plainData := givenTypicalNamedValueModel()

	pollerMock := &NamedValuePollerMock[armapimanagement.NamedValueClientCreateOrUpdateResponse]{}
	pollerMock.GivenPollingSucceeds(armapimanagement.NamedValueClientCreateOrUpdateResponse{})

	clMock := &NamedValueClientMock{}
	clMock.GivenBeginCreateOrUpdate(
		mdl.DestinationNamedValue.ResourceGroup.ValueString(),
		mdl.DestinationNamedValue.ServiceName.ValueString(),
		mdl.DestinationNamedValue.Name.ValueString(),
		pollerMock,
	)

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimNamedValueClient(
		mdl.DestinationNamedValue.AzSubscriptionId.ValueString(),
		clMock,
	)

	ks := &NamedValueSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, plainData)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	pollerMock.AssertExpectations(t)
	clMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_NV_WillReturnNewResource(t *testing.T) {
	rv := NewNamedValueResource()
	assert.NotNil(t, rv)
}

func Test_NV_ResourceRequest(t *testing.T) {
	rv := NewNamedValueResource()

	mdReq := resource.MetadataRequest{
		ProviderTypeName: "az-confidential",
	}
	mdResp := resource.MetadataResponse{}
	rv.Metadata(context.Background(), mdReq, &mdResp)
	assert.Equal(t, "az-confidential_apim_named_value", mdResp.TypeName)
}
