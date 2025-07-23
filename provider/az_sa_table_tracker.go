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
	rowEntity, err := a.getEntity(ctx, id)
	if err != nil {
		return false, err
	} else {
		return rowEntity != nil, nil
	}
}

func (a *AzStorageAccountTableTracker) GetTackedObjectUses(ctx context.Context, id string) (int, error) {
	rowEntity, err := a.getEntity(ctx, id)
	if err != nil || rowEntity == nil {
		return 0, err
	} else {
		return a.getNumUses(rowEntity), nil
	}
}

func (a *AzStorageAccountTableTracker) getEntity(ctx context.Context, id string) (*aztables.EDMEntity, error) {
	client, err := a.getTableClient()
	if err != nil {
		return nil, err
	}

	filter := fmt.Sprintf("PartitionKey eq '%s' and RowKey eq '%s'", a.PartitionKey, id)
	options := &aztables.ListEntitiesOptions{
		Filter: &filter,
		Select: to.Ptr("RowKey,PartitionKey,numUses"),
		Top:    to.Ptr(int32(15)),
	}

	pager := client.NewListEntitiesPager(options)

	records, err := pager.NextPage(ctx)
	if err != nil {
		return nil, err
	} else if len(records.Entities) != 1 {
		return nil, err
	}

	rv := aztables.EDMEntity{}
	err = json.Unmarshal(records.Entities[0], &rv)

	return &rv, err
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
	client, err := a.getTableClient()
	if err != nil {
		return fmt.Errorf("cannot retrieve table client: %v", err.Error())
	}

	tableRec, err := a.getEntity(ctx, id)
	if err != nil {
		return err
	}

	if tableRec == nil {
		tableRec = &aztables.EDMEntity{
			Entity: aztables.Entity{
				PartitionKey: a.PartitionKey,
				RowKey:       id,
			},
			Properties: map[string]any{
				"trackedAt":        time.Now().Unix(),
				"trackedTimestamp": time.Now().Format(time.RFC3339),
				"numUses":          1,
			},
		}

		marshalled, _ := json.Marshal(tableRec)

		_, err = client.AddEntity(ctx, marshalled, nil)
		if err != nil {
			return fmt.Errorf("cannot track object id: %s", err.Error())
		}
	} else {
		tableRec.Properties["numUses"] = a.getNumUses(tableRec) + 1
		tableRec.Properties["updatedAt"] = time.Now().Unix()
		tableRec.Properties["updatedAtTimestamp"] = time.Now().Format(time.RFC3339)

		marshalled, _ := json.Marshal(tableRec)

		_, err = client.UpdateEntity(ctx, marshalled, nil)
		if err != nil {
			return fmt.Errorf("cannot track updated use of confidential object: %s", err.Error())
		}
	}

	return nil
}

func (a *AzStorageAccountTableTracker) getNumUses(tableRec *aztables.EDMEntity) int {
	numUses := 0

	if numUsesValue, keyExists := tableRec.Properties["numUses"]; keyExists {
		numUses = int(numUsesValue.(int32))
	}
	return numUses
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
