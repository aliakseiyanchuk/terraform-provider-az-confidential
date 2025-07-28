package apim

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

//----------------------------------------------------------------------------------------------------------
// SubscriptionModel test cases

func Test_SubscriptionModel_Accept(t *testing.T) {
	sm := SubscriptionModel{}
	p := armapimanagement.SubscriptionContract{
		ID: to.Ptr("/subscriptions/azSid/resourceGroups/rg/providers/Microsoft.ApiManagement/service/sn/subscriptions/subId"),
		Properties: &armapimanagement.SubscriptionContractProperties{
			Scope:        to.Ptr("/apis/abc"),
			State:        to.Ptr(armapimanagement.SubscriptionStateActive),
			AllowTracing: to.Ptr(true),
			DisplayName:  to.Ptr("sd-displayName"),
			OwnerID:      to.Ptr("userId"),
		},
	}

	sm.Accept(p)

	assert.Equal(t, "/subscriptions/azSid/resourceGroups/rg/providers/Microsoft.ApiManagement/service/sn/subscriptions/subId", sm.Id.ValueString())
	assert.Equal(t, "abc", sm.DestinationSubscription.APIIdentifier.ValueString())
	assert.Equal(t, "", sm.DestinationSubscription.ProductIdentifier.ValueString())
	assert.Equal(t, "userId", sm.DestinationSubscription.UserIdentifier.ValueString())
	assert.Equal(t, "sd-displayName", sm.DisplayName.ValueString())
}

//----------------------------------------------------------------------------------------------------------

func TestNewConfidentialSubscriptionResourceWillReturn(t *testing.T) {
	_ = NewSubscriptionResource()
}

func givenTypicalSubscriptionModel() (SubscriptionModel, ConfidentialSubscriptionData) {
	nvModel := SubscriptionModel{
		SubscriptionId: types.StringValue("subscriptionId"),
		State:          types.StringValue("active"),
		DisplayName:    types.StringUnknown(),
		AllowTracing:   types.BoolValue(false),
		DestinationSubscription: DestinationSubscriptionCoordinateModel{
			DestinationApiManagement: DestinationApiManagement{
				AzSubscriptionId: types.StringValue(""),
				ResourceGroup:    types.StringValue("resourceGroup"),
				ServiceName:      types.StringValue("apimServiceName"),
			},
			SubscriptionId:    types.StringValue("subscriptionId"),
			APIIdentifier:     types.StringUnknown(),
			ProductIdentifier: types.StringUnknown(),
			UserIdentifier:    types.StringUnknown(),
		},
	}
	nvModel.Id = types.StringValue("/subscriptions/azSubscriptionId/resourceGroups/resourceGroup/providers/Microsoft.ApiManagement/service/apimServiceName/subscriptions/subscriptionId")
	plainData := ConfidentialSubscriptionStruct{
		PrimaryKey:   "a",
		SecondaryKey: "b",
	}

	return nvModel, &plainData
}

func givenTypicalSubscriptionModelBeforeCreate() (SubscriptionModel, ConfidentialSubscriptionData) {
	rv, confDat := givenTypicalSubscriptionModel()
	rv.Id = types.StringUnknown()

	return rv, confDat
}

func Test_Sub_DoReadIfNoSubscriptionExists(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscriptionErrs("", "unit-test-error")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Missing Azure subscription Id", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfObjectIdIsMalFormed(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()
	mdl.Id = types.StringValue("this is not a valid identifier")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Resource identifier is malformed", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadWillDetectImplicitMove(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()
	mdl.Id = types.StringValue("/subscriptions/movedAzSubscriptionId/resourceGroups/resourceGroup/providers/Microsoft.ApiManagement/service/apimServiceName/subscriptions/subscriptionId")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Implicit move", dg[0].Summary())
	assert.Equal(t, "This APIM subscription is created in Azure subscription movedAzSubscriptionId, whereas the configuration now requires it to be created in Azure subscription azSubscriptionId. Delete and recreate this resource", dg[0].Detail())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfSubscriptionClientErrs(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClientErrs("azSubscriptionId", "unit-test-error")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire APIM subscription client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfSubscriptionClientIsNil(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClientIsNil("azSubscriptionId")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire APIM subscription client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfGetOperationErrs(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenGetErrs("resourceGroup", "apimServiceName", "subscriptionId", "unit-test-error")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot read subscription", dg[0].Summary())

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfGetNotFoundWithoutProviderTracing(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenGetReturnsNotFound("resourceGroup", "apimServiceName", "subscriptionId")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenIsObjectTrackingEnabled(false)
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceNotFound, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfGetNotFoundWithProviderTracing(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenGetReturnsNotFound("resourceGroup", "apimServiceName", "subscriptionId")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenIsObjectTrackingEnabled(true)
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceNotFound, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 1, len(dg))
	assert.Equal(t, "Subscription removed from API management", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfListSecretsErrs(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenGetReturns("resourceGroup", "apimServiceName", "subscriptionId")
	clientMock.GivenListSecretsErrs("resourceGroup", "apimServiceName", "subscriptionId", "unit-test-error")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot read subscription keys", dg[0].Summary())

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoReadIfDriftIsFound(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenGetReturns("resourceGroup", "apimServiceName", "subscriptionId")
	clientMock.GivenListSecretsReturns("resourceGroup", "apimServiceName", "subscriptionId", "drifted-a", "drifted-b")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceConfidentialDataDrift, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 1, len(dg))
	assert.Equal(t, "Subscription keys have drifted from the state declared in ciphertext", dg[0].Summary())

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoRead(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenGetReturns("resourceGroup", "apimServiceName", "subscriptionId")
	clientMock.GivenListSecretsReturns("resourceGroup", "apimServiceName", "subscriptionId", "a", "b")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl, confData)
	assert.Equal(t, resources.ResourceExists, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoCreateIfNoSubscriptionIsConfigured(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModelBeforeCreate()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscriptionErrs("", "unit-test-error")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Missing Azure subscription Id", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoCreateIfSubscriptionClientErrs(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModelBeforeCreate()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClientErrs("azSubscriptionId", "unit-test-error")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire APIM subscription client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoCreateIfSubscriptionClientIsNil(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModelBeforeCreate()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClientIsNil("azSubscriptionId")

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire APIM subscription client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoCreateIfCreateOrUpdateFail(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModelBeforeCreate()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenCreateOrUpdateErrs("resourceGroup", "apimServiceName", "subscriptionId", "unit-test-error")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot create subscription", dg[0].Summary())

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoCreate(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModelBeforeCreate()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenCreateOrUpdate("resourceGroup", "apimServiceName", "subscriptionId")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetAzSubscription("", "azSubscriptionId")
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confData)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoUpdateIfIdIsMalformed(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()
	mdl.Id = types.StringValue("this is not a valid identifier")

	ks := SubscriptionSpecializer{}

	_, dg := ks.DoUpdate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Resource identifier is malformed", dg[0].Summary())

}

func Test_Sub_DoUpdateIfGetClientErrs(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClientErrs("azSubscriptionId", "unit-test-error")

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "APIM subscription client cannot be retrieved", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoUpdateIfGetClientIsNil(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClientIsNil("azSubscriptionId")

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "APIM subscription client cannot be retrieved", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoUpdateIfUpdateErrs(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenUpdateErrs("resourceGroup", "apimServiceName", "subscriptionId", "unit-test-error")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot update subscription", dg[0].Summary())

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoUpdateIfUpdate(t *testing.T) {
	mdl, confData := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenUpdate("resourceGroup", "apimServiceName", "subscriptionId")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	_, dg := ks.DoUpdate(context.Background(), &mdl, confData)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	clientMock.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_Sub_WillReturnResource(t *testing.T) {
	r := NewSubscriptionResource()
	assert.NotNil(t, r)
}

func Test_Sub_WillYieldResource(t *testing.T) {
	r := NewSubscriptionResource()
	assert.NotNil(t, r)

	req := resource.MetadataRequest{
		ProviderTypeName: "az-confidential",
	}
	resp := resource.MetadataResponse{}
	r.Metadata(context.Background(), req, &resp)

	assert.Equal(t, "az-confidential_apim_subscription", resp.TypeName)
}

func Test_Sub_DeleteIfIdIsMalformed(t *testing.T) {
	mdl, _ := givenTypicalSubscriptionModel()
	mdl.Id = types.StringValue("this is not a valid identifier")

	ks := SubscriptionSpecializer{}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Resource identifier is malformed", dg[0].Summary())
}

func Test_Sub_DoDeleteIfGetClientErrs(t *testing.T) {
	mdl, _ := givenTypicalSubscriptionModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClientErrs("azSubscriptionId", "unit-test-error")

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "APIM subscription client cannot be retrieved", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoDeleteIfGetClientIsNil(t *testing.T) {
	mdl, _ := givenTypicalSubscriptionModel()

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClientIsNil("azSubscriptionId")

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "APIM subscription client cannot be retrieved", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoDeleteIfDeleteFails(t *testing.T) {
	mdl, _ := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenDeleteErrs("resourceGroup", "apimServiceName", "subscriptionId", "unit-test-error")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot delete API Management subscription", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_Sub_DoDelete(t *testing.T) {
	mdl, _ := givenTypicalSubscriptionModel()

	clientMock := &SubscriptionClientMock{}
	clientMock.GivenDeleteReturns("resourceGroup", "apimServiceName", "subscriptionId")

	factoryMock := &AZClientsFactoryMock{}
	factoryMock.GivenGetApimSubscriptionClient("azSubscriptionId", clientMock)

	ks := SubscriptionSpecializer{
		factory: factoryMock,
	}

	dg := ks.DoDelete(context.Background(), &mdl)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))

	factoryMock.AssertExpectations(t)
}
