package apim

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/stretchr/testify/mock"
)

func MockedAzObjectNotFoundError() error {
	return errors.New("---------------\nRESPONSE 404: 404 Not Found")
}

type SubscriptionClientMock struct {
	mock.Mock
	core.ApimSubscriptionClientAbstraction
}

func (sc *SubscriptionClientMock) GivenUpdateErrs(resourceGroupName, serviceName, subId, errMsg string) {
	var getOps *armapimanagement.SubscriptionClientUpdateOptions = nil
	sc.On("Update", mock.Anything, resourceGroupName, serviceName, subId, "*", mock.Anything, getOps).
		Return(armapimanagement.SubscriptionClientUpdateResponse{}, errors.New(errMsg))
}

func (sc *SubscriptionClientMock) GivenUpdate(resourceGroupName, serviceName, subId string) {
	var getOps *armapimanagement.SubscriptionClientUpdateOptions = nil
	sc.On("Update", mock.Anything, resourceGroupName, serviceName, subId, "*", mock.Anything, getOps).
		Return(armapimanagement.SubscriptionClientUpdateResponse{}, nil)
}

func (sc *SubscriptionClientMock) GivenCreateOrUpdateErrs(resourceGroupName, serviceName, subId, errMsg string) {
	var getOps *armapimanagement.SubscriptionClientCreateOrUpdateOptions = nil
	sc.On("CreateOrUpdate", mock.Anything, resourceGroupName, serviceName, subId, mock.Anything, getOps).
		Return(armapimanagement.SubscriptionClientCreateOrUpdateResponse{}, errors.New(errMsg))
}

func (sc *SubscriptionClientMock) GivenCreateOrUpdate(resourceGroupName, serviceName, subId string) {
	var getOps *armapimanagement.SubscriptionClientCreateOrUpdateOptions = nil
	sc.On("CreateOrUpdate", mock.Anything, resourceGroupName, serviceName, subId, mock.Anything, getOps).
		Return(armapimanagement.SubscriptionClientCreateOrUpdateResponse{}, nil)
}

func (sc *SubscriptionClientMock) GivenListSecretsErrs(resourceGroupName, serviceName, subId, errMsg string) {
	var getOps *armapimanagement.SubscriptionClientListSecretsOptions = nil
	sc.On("ListSecrets", mock.Anything, resourceGroupName, serviceName, subId, getOps).
		Return(armapimanagement.SubscriptionClientListSecretsResponse{}, errors.New(errMsg))
}

func (sc *SubscriptionClientMock) GivenListSecretsReturns(resourceGroupName, serviceName, subId, pk, sk string) {
	var getOps *armapimanagement.SubscriptionClientListSecretsOptions = nil
	sc.On("ListSecrets", mock.Anything, resourceGroupName, serviceName, subId, getOps).
		Return(armapimanagement.SubscriptionClientListSecretsResponse{
			SubscriptionKeysContract: armapimanagement.SubscriptionKeysContract{
				PrimaryKey:   to.Ptr(pk),
				SecondaryKey: to.Ptr(sk),
			},
		}, nil)
}

func (sc *SubscriptionClientMock) GivenDeleteErrs(resourceGroupName, serviceName, subId, errMsg string) {
	var deleteOpts *armapimanagement.SubscriptionClientDeleteOptions = nil
	sc.On("Delete", mock.Anything, resourceGroupName, serviceName, subId, "*", deleteOpts).
		Return(armapimanagement.SubscriptionClientDeleteResponse{}, errors.New(errMsg))
}

func (sc *SubscriptionClientMock) GivenDeleteReturns(resourceGroupName, serviceName, subId string) {
	var deleteOps *armapimanagement.SubscriptionClientDeleteOptions = nil
	sc.On("Delete", mock.Anything, resourceGroupName, serviceName, subId, "*", deleteOps).
		Return(armapimanagement.SubscriptionClientDeleteResponse{}, nil)
}

func (sc *SubscriptionClientMock) GivenGetErrs(resourceGroupName, serviceName, subId, errMsg string) {
	var getOps *armapimanagement.SubscriptionClientGetOptions = nil
	sc.On("Get", mock.Anything, resourceGroupName, serviceName, subId, getOps).
		Return(armapimanagement.SubscriptionClientGetResponse{}, errors.New(errMsg))
}

func (sc *SubscriptionClientMock) GivenGetReturnsNotFound(resourceGroupName, serviceName, subId string) {
	var getOps *armapimanagement.SubscriptionClientGetOptions = nil
	sc.On("Get", mock.Anything, resourceGroupName, serviceName, subId, getOps).
		Return(armapimanagement.SubscriptionClientGetResponse{}, MockedAzObjectNotFoundError())
}

func (sc *SubscriptionClientMock) GivenGetReturns(resourceGroupName, serviceName, subId string) {
	var getOps *armapimanagement.SubscriptionClientGetOptions = nil
	sc.On("Get", mock.Anything, resourceGroupName, serviceName, subId, getOps).
		Return(armapimanagement.SubscriptionClientGetResponse{}, nil)
}

func (sc *SubscriptionClientMock) Get(ctx context.Context, resourceGroupName string, serviceName string, sid string, options *armapimanagement.SubscriptionClientGetOptions) (armapimanagement.SubscriptionClientGetResponse, error) {
	args := sc.Called(ctx, resourceGroupName, serviceName, sid, options)
	return args.Get(0).(armapimanagement.SubscriptionClientGetResponse), args.Error(1)
}

func (sc *SubscriptionClientMock) ListSecrets(ctx context.Context, resourceGroupName string, serviceName string, sid string, options *armapimanagement.SubscriptionClientListSecretsOptions) (armapimanagement.SubscriptionClientListSecretsResponse, error) {
	args := sc.Called(ctx, resourceGroupName, serviceName, sid, options)
	return args.Get(0).(armapimanagement.SubscriptionClientListSecretsResponse), args.Error(1)
}

func (sc *SubscriptionClientMock) CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, sid string, parameters armapimanagement.SubscriptionCreateParameters, options *armapimanagement.SubscriptionClientCreateOrUpdateOptions) (armapimanagement.SubscriptionClientCreateOrUpdateResponse, error) {
	args := sc.Called(ctx, resourceGroupName, serviceName, sid, parameters, options)
	return args.Get(0).(armapimanagement.SubscriptionClientCreateOrUpdateResponse), args.Error(1)
}

func (sc *SubscriptionClientMock) Update(ctx context.Context, resourceGroupName string, serviceName string, sid string, ifMatch string, parameters armapimanagement.SubscriptionUpdateParameters, options *armapimanagement.SubscriptionClientUpdateOptions) (armapimanagement.SubscriptionClientUpdateResponse, error) {
	args := sc.Called(ctx, resourceGroupName, serviceName, sid, ifMatch, parameters, options)
	return args.Get(0).(armapimanagement.SubscriptionClientUpdateResponse), args.Error(1)
}

func (sc *SubscriptionClientMock) Delete(ctx context.Context, resourceGroupName string, serviceName string, sid string, ifMatch string, options *armapimanagement.SubscriptionClientDeleteOptions) (armapimanagement.SubscriptionClientDeleteResponse, error) {
	args := sc.Called(ctx, resourceGroupName, serviceName, sid, ifMatch, options)
	return args.Get(0).(armapimanagement.SubscriptionClientDeleteResponse), args.Error(1)
}

type NamedValuePollerMock[T any] struct {
	mock.Mock
	core.PollerAbstraction[T]
}

func (nvp *NamedValuePollerMock[T]) PollUntilDone(ctx context.Context, options *runtime.PollUntilDoneOptions) (res T, err error) {
	args := nvp.Called(ctx, options)
	return args.Get(0).(T), args.Error(1)
}

func (nvp *NamedValuePollerMock[T]) GivenPollingErrs(defaultValue T, errMsg string) {
	var pollOpts *runtime.PollUntilDoneOptions
	nvp.On("PollUntilDone", mock.Anything, pollOpts).
		Return(defaultValue, errors.New(errMsg))
}

func (nvp *NamedValuePollerMock[T]) GivenPollingSucceeds(defaultValue T) {
	var pollOpts *runtime.PollUntilDoneOptions
	nvp.On("PollUntilDone", mock.Anything, pollOpts).
		Return(defaultValue, nil)
}

type NamedValueClientMock struct {
	mock.Mock
	core.ApimNamedValueClientAbstraction
}

func (n *NamedValueClientMock) Get(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, options *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error) {
	args := n.Called(ctx, resourceGroupName, serviceName, namedValueID, options)
	return args.Get(0).(armapimanagement.NamedValueClientGetResponse), args.Error(1)
}

func (n *NamedValueClientMock) GivenGetErrs(resourceGroupName string, serviceName string, namedValueID, errMsg string) {
	var getOps *armapimanagement.NamedValueClientGetOptions = nil

	n.On("Get", mock.Anything, resourceGroupName, serviceName, namedValueID, getOps).
		Return(armapimanagement.NamedValueClientGetResponse{}, errors.New(errMsg))
}

func (n *NamedValueClientMock) GivenGet(resourceGroupName string, serviceName string, namedValueID string) {
	var getOps *armapimanagement.NamedValueClientGetOptions = nil

	n.On("Get", mock.Anything, resourceGroupName, serviceName, namedValueID, getOps).
		Return(armapimanagement.NamedValueClientGetResponse{}, nil)
}

func (n *NamedValueClientMock) GivenGetReturnsNotFound(resourceGroupName string, serviceName string, namedValueID string) {
	var getOps *armapimanagement.NamedValueClientGetOptions = nil

	n.On("Get", mock.Anything, resourceGroupName, serviceName, namedValueID, getOps).
		Return(armapimanagement.NamedValueClientGetResponse{}, MockedAzObjectNotFoundError())
}

func (n *NamedValueClientMock) ListValue(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, options *armapimanagement.NamedValueClientListValueOptions) (armapimanagement.NamedValueClientListValueResponse, error) {
	args := n.Called(ctx, resourceGroupName, serviceName, namedValueID, options)
	return args.Get(0).(armapimanagement.NamedValueClientListValueResponse), args.Error(1)
}

func (n *NamedValueClientMock) GivenListValueErrs(resourceGroupName string, serviceName string, namedValueID, errMsg string) {
	var getOps *armapimanagement.NamedValueClientListValueOptions = nil

	n.On("ListValue", mock.Anything, resourceGroupName, serviceName, namedValueID, getOps).
		Return(armapimanagement.NamedValueClientGetResponse{}, errors.New(errMsg))
}

func (n *NamedValueClientMock) GivenListValueReturns(resourceGroupName string, serviceName string, namedValueID string, value *string) {
	var getOps *armapimanagement.NamedValueClientListValueOptions = nil

	n.On("ListValue", mock.Anything, resourceGroupName, serviceName, namedValueID, getOps).
		Return(armapimanagement.NamedValueClientListValueResponse{
			NamedValueSecretContract: armapimanagement.NamedValueSecretContract{
				Value: value,
			},
			ETag: to.Ptr("somethng"),
		}, nil)
}

func (n *NamedValueClientMock) Delete(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, options *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error) {
	args := n.Called(ctx, resourceGroupName, serviceName, namedValueID, ifMatch, options)
	return args.Get(0).(armapimanagement.NamedValueClientDeleteResponse), args.Error(1)
}

func (n *NamedValueClientMock) GivenDeleteErrs(resourceGroupName string, serviceName string, namedValueID string, errMsg string) {
	var deleteOpts *armapimanagement.NamedValueClientDeleteOptions = nil
	n.On("Delete", mock.Anything, resourceGroupName, serviceName, namedValueID, "*", deleteOpts).
		Return(armapimanagement.NamedValueClientDeleteResponse{}, errors.New(errMsg))
}

func (n *NamedValueClientMock) GivenDelete(resourceGroupName string, serviceName string, namedValueID string) {
	var deleteOpts *armapimanagement.NamedValueClientDeleteOptions = nil
	n.On("Delete", mock.Anything, resourceGroupName, serviceName, namedValueID, "*", deleteOpts).
		Return(armapimanagement.NamedValueClientDeleteResponse{}, nil)
}

func (n *NamedValueClientMock) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, parameters armapimanagement.NamedValueCreateContract, options *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (core.PollerAbstraction[armapimanagement.NamedValueClientCreateOrUpdateResponse], error) {
	args := n.Called(ctx, resourceGroupName, serviceName, namedValueID, parameters, options)

	var rv core.PollerAbstraction[armapimanagement.NamedValueClientCreateOrUpdateResponse] = nil
	if args.Get(0) != nil {
		rv = args.Get(0).(core.PollerAbstraction[armapimanagement.NamedValueClientCreateOrUpdateResponse])
	}

	return rv, args.Error(1)
}

func (n *NamedValueClientMock) GivenBeginCreateOrUpdateErrs(resourceGroupName string, serviceName string, namedValueID string, errorMessage string) {
	var beginOrUpdateOpts *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions = nil
	n.On("BeginCreateOrUpdate", mock.Anything, resourceGroupName, serviceName, namedValueID, mock.Anything, beginOrUpdateOpts).
		Return(nil, errors.New(errorMessage))
}

func (n *NamedValueClientMock) GivenBeginCreateOrUpdate(resourceGroupName string, serviceName string, namedValueID string, poller core.PollerAbstraction[armapimanagement.NamedValueClientCreateOrUpdateResponse]) {
	var beginOrUpdateOpts *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions = nil
	n.On("BeginCreateOrUpdate", mock.Anything, resourceGroupName, serviceName, namedValueID, mock.Anything, beginOrUpdateOpts).
		Return(poller, nil)
}

func (n *NamedValueClientMock) BeginUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, parameters armapimanagement.NamedValueUpdateParameters, options *armapimanagement.NamedValueClientBeginUpdateOptions) (core.PollerAbstraction[armapimanagement.NamedValueClientUpdateResponse], error) {
	args := n.Called(ctx, resourceGroupName, serviceName, namedValueID, ifMatch, parameters, options)

	var rv core.PollerAbstraction[armapimanagement.NamedValueClientUpdateResponse] = nil
	if args.Get(0) != nil {
		rv = args.Get(0).(core.PollerAbstraction[armapimanagement.NamedValueClientUpdateResponse])
	}

	return rv, args.Error(1)
}

func (n *NamedValueClientMock) GivenBeginUpdateErrs(resourceGroupName string, serviceName string, namedValueID string, errorMessage string) {
	var beginOrUpdateOpts *armapimanagement.NamedValueClientBeginUpdateOptions = nil
	n.On("BeginUpdate", mock.Anything, resourceGroupName, serviceName, namedValueID, "*", mock.Anything, beginOrUpdateOpts).
		Return(nil, errors.New(errorMessage))
}

func (n *NamedValueClientMock) GivenBeginUpdate(resourceGroupName string, serviceName string, namedValueID string, poller core.PollerAbstraction[armapimanagement.NamedValueClientUpdateResponse]) {
	var beginOrUpdateOpts *armapimanagement.NamedValueClientBeginUpdateOptions = nil
	n.On("BeginUpdate", mock.Anything, resourceGroupName, serviceName, namedValueID, "*", mock.Anything, beginOrUpdateOpts).
		Return(poller, nil)
}

type AZClientsFactoryMock struct {
	core.AZClientsFactory
	mock.Mock
}

func (m *AZClientsFactoryMock) GivenGetApimNamedValueClientErrs(subId, errMsg string) {
	m.On("GetApimNamedValueClient", subId).
		Return(nil, errors.New(errMsg))
}

func (m *AZClientsFactoryMock) GivenGetApimNamedValueClientIsNil(subId string) {
	m.On("GetApimNamedValueClient", subId).
		Return(nil, nil)
}

func (m *AZClientsFactoryMock) GivenGetApimNamedValueClient(subId string, cl core.ApimNamedValueClientAbstraction) {
	m.On("GetApimNamedValueClient", subId).
		Return(cl, nil)
}

func (m *AZClientsFactoryMock) GivenGetApimSubscriptionClientErrs(subId, errMsg string) {
	m.On("GetApimSubscriptionClient", subId).
		Return(nil, errors.New(errMsg))
}

func (m *AZClientsFactoryMock) GivenGetApimSubscriptionClientIsNil(subId string) {
	m.On("GetApimSubscriptionClient", subId).
		Return(nil, nil)
}

func (m *AZClientsFactoryMock) GivenGetApimSubscriptionClient(subId string, cl core.ApimSubscriptionClientAbstraction) {
	m.On("GetApimSubscriptionClient", subId).
		Return(cl, nil)
}

func (m *AZClientsFactoryMock) GetApimNamedValueClient(subId string) (core.ApimNamedValueClientAbstraction, error) {
	args := m.Called(subId)

	var rv core.ApimNamedValueClientAbstraction
	if args.Get(0) != nil {
		rv = args.Get(0).(core.ApimNamedValueClientAbstraction)
	}

	return rv, args.Error(1)
}

func (m *AZClientsFactoryMock) GetApimSubscriptionClient(subId string) (core.ApimSubscriptionClientAbstraction, error) {
	args := m.Called(subId)

	var rv core.ApimSubscriptionClientAbstraction
	if args.Get(0) != nil {
		rv = args.Get(0).(core.ApimSubscriptionClientAbstraction)
	}

	return rv, args.Error(1)
}

func (m *AZClientsFactoryMock) IsObjectIdTracked(ctx context.Context, id string) (bool, error) {
	rv := m.Mock.Called(ctx, id)
	return rv.Get(0).(bool), rv.Error(1)
}

func (m *AZClientsFactoryMock) GetTackedObjectUses(ctx context.Context, id string) (int, error) {
	rv := m.Mock.Called(ctx, id)
	return rv.Get(0).(int), rv.Error(1)
}

func (m *AZClientsFactoryMock) IsObjectTrackingEnabled() bool {
	rv := m.Mock.Called()
	return rv.Get(0).(bool)
}

func (m *AZClientsFactoryMock) GivenIsObjectTrackingEnabled(enableOpt bool) {
	m.On("IsObjectTrackingEnabled").Return(enableOpt)
}

func (m *AZClientsFactoryMock) GetAzSubscription(v string) (string, error) {
	rv := m.Mock.Called(v)
	return rv.Get(0).(string), rv.Error(1)
}

func (m *AZClientsFactoryMock) GivenGetAzSubscriptionErrs(inSub, errMsg string) {
	m.On("GetAzSubscription", inSub).
		Return(inSub, errors.New(errMsg))
}

func (m *AZClientsFactoryMock) GivenGetAzSubscription(inSub, rvSub string) {
	m.On("GetAzSubscription", inSub).
		Return(rvSub, nil)
}
