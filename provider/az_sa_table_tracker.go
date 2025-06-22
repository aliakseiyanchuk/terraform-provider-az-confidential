package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/data/aztables"
	"time"
)

type AzStorageAccountTableTracker struct {
	Credential azcore.TokenCredential

	AccountName  string
	TableName    string
	PartitionKey string

	service     *aztables.ServiceClient
	tableClient *aztables.Client
}

func (a *AzStorageAccountTableTracker) IsObjectIdTracked(ctx context.Context, id string) (bool, error) {
	client, err := a.getTableClient()
	if err != nil {
		return false, err
	}

	filter := fmt.Sprintf("PartitionKey eq '%s' and RowKey eq '%s'", a.PartitionKey, id)
	options := &aztables.ListEntitiesOptions{
		Filter: &filter,
		Select: to.Ptr("RowKey,Value"),
		Top:    to.Ptr(int32((15))),
	}

	pager := client.NewListEntitiesPager(options)

	records, err := pager.NextPage(ctx)
	if err != nil {
		return false, err
	}

	return records.Entities != nil, nil
}

func (a *AzStorageAccountTableTracker) getTableClient() (*aztables.Client, error) {
	if a.service == nil {
		svc, initErr := aztables.NewServiceClient(
			fmt.Sprintf("https://%s.table.core.windows.net", a.AccountName),
			a.Credential,
			nil)

		if initErr != nil {
			return nil, fmt.Errorf("unable to create service client: %s", initErr.Error())
		} else {
			a.service = svc
		}
	}

	if a.tableClient == nil {
		a.tableClient = a.service.NewClient(a.TableName)
	}

	return a.tableClient, nil
}

func (a *AzStorageAccountTableTracker) TrackObjectId(ctx context.Context, id string) error {
	tableRec := aztables.EDMEntity{
		Entity: aztables.Entity{
			PartitionKey: a.PartitionKey,
			RowKey:       id,
		},
		Properties: map[string]any{
			"trackedAt":        time.Now().Unix(),
			"trackedTimestamp": time.Now().Format(time.RFC3339),
		},
	}

	marshalled, _ := json.Marshal(tableRec)

	client, err := a.getTableClient()
	if err != nil {
		return fmt.Errorf("cannot retrieve table client: %v", err.Error())
	}

	_, err = client.AddEntity(ctx, marshalled, nil)
	if err != nil {
		return fmt.Errorf("cannot track object id: %s", err.Error())
	}

	return nil
}

func NewAzStorageAccountTracker(cred azcore.TokenCredential, accountName, tableName, partitionKey string) (*AzStorageAccountTableTracker, error) {
	rv := &AzStorageAccountTableTracker{
		Credential:   cred,
		AccountName:  accountName,
		TableName:    tableName,
		PartitionKey: partitionKey,
	}
	return rv, nil
}
