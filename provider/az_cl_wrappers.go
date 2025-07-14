package provider

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

type ApimNamedValueClientAbstractionWrapper struct {
	client *armapimanagement.NamedValueClient
}

func (a *ApimNamedValueClientAbstractionWrapper) Get(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, options *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error) {
	return a.client.Get(ctx, resourceGroupName, serviceName, namedValueID, options)
}

func (a *ApimNamedValueClientAbstractionWrapper) ListValue(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, options *armapimanagement.NamedValueClientListValueOptions) (armapimanagement.NamedValueClientListValueResponse, error) {
	return a.client.ListValue(ctx, resourceGroupName, serviceName, namedValueID, options)
}

func (a *ApimNamedValueClientAbstractionWrapper) Delete(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, options *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error) {
	return a.client.Delete(ctx, resourceGroupName, serviceName, namedValueID, ifMatch, options)
}

func (a *ApimNamedValueClientAbstractionWrapper) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, parameters armapimanagement.NamedValueCreateContract, options *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (core.PollerAbstraction[armapimanagement.NamedValueClientCreateOrUpdateResponse], error) {
	return a.client.BeginCreateOrUpdate(ctx, resourceGroupName, serviceName, namedValueID, parameters, options)
}

func (a *ApimNamedValueClientAbstractionWrapper) BeginUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, parameters armapimanagement.NamedValueUpdateParameters, options *armapimanagement.NamedValueClientBeginUpdateOptions) (core.PollerAbstraction[armapimanagement.NamedValueClientUpdateResponse], error) {
	return a.client.BeginUpdate(ctx, resourceGroupName, serviceName, namedValueID, ifMatch, parameters, options)
}
