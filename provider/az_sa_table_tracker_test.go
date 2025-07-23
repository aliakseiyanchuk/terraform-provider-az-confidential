package provider

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func getTestAzCredential(t *testing.T) *azidentity.ClientSecretCredential {
	tenantId := os.Getenv("TF_VAR_az_tenant_id")
	clientID := os.Getenv("TF_VAR_az_client_id")
	secret := os.Getenv("TF_VAR_az_client_secret")

	if len(tenantId) == 0 || len(clientID) == 0 || len(secret) == 0 {
		return nil
	}

	cred, err := azidentity.NewClientSecretCredential(
		tenantId,
		clientID,
		secret,
		nil,
	)

	assert.Nil(t, err, "Failed to create credential")
	return cred
}

func Test_AZTATT_Integration(t *testing.T) {
	cred := getTestAzCredential(t)
	if cred == nil {
		t.SkipNow()
		fmt.Println("Az Table Tracker integration test skipped: no credential set")
		return
	}

	tracker := AzStorageAccountTableTracker{
		Credential:   cred,
		AccountName:  os.Getenv("AZ_SA_ACCOUNT_NAME"),
		TableName:    os.Getenv("AZ_SA_TABLE_NAME"),
		PartitionKey: "acctest",
	}

	fmt.Println("---object existence --")

	testUUID := uuid.New().String()

	ctx := context.Background()

	tracked, trackCheckErr := tracker.IsObjectIdTracked(ctx, testUUID)
	assert.Nil(t, trackCheckErr)
	assert.False(t, tracked)

	trackStoreErr := tracker.TrackObjectId(ctx, testUUID)
	assert.Nil(t, trackStoreErr)

	fmt.Println("---object existence -2-")

	tracked, trackCheckErr = tracker.IsObjectIdTracked(ctx, testUUID)
	assert.Nil(t, trackCheckErr)
	assert.True(t, tracked)
}

func Test_AZTATT_ObjectCounting_Integration(t *testing.T) {
	cred := getTestAzCredential(t)
	if cred == nil {
		t.SkipNow()
		fmt.Println("Az Table Tracker integration test skipped: no credential set")
		return
	}

	tracker := AzStorageAccountTableTracker{
		Credential:   cred,
		AccountName:  os.Getenv("AZ_SA_ACCOUNT_NAME"),
		TableName:    os.Getenv("AZ_SA_TABLE_NAME"),
		PartitionKey: "acctest_oc",
	}

	fmt.Println("---object counting--")

	testUUID := uuid.New().String()

	ctx := context.Background()

	tracked, trackCheckErr := tracker.GetTackedObjectUses(ctx, testUUID)
	assert.Nil(t, trackCheckErr)
	assert.Equal(t, 0, tracked)

	fmt.Println("---first iteration--")

	// First iteration:
	trackStoreErr := tracker.TrackObjectId(ctx, testUUID)
	assert.Nil(t, trackStoreErr)

	fmt.Println("---check first ujse--")

	tracked, trackCheckErr = tracker.GetTackedObjectUses(ctx, testUUID)
	assert.Nil(t, trackCheckErr)
	assert.Equal(t, 1, tracked)

	fmt.Println("---check tracked--")

	tc, trackCheckErr := tracker.IsObjectIdTracked(ctx, testUUID)
	assert.Nil(t, trackCheckErr)
	assert.True(t, tc)

	fmt.Println("---second track--")

	// First iteration:
	trackStoreErr = tracker.TrackObjectId(ctx, testUUID)
	assert.Nil(t, trackStoreErr)

	fmt.Println("---check second use--")

	tracked, trackCheckErr = tracker.GetTackedObjectUses(ctx, testUUID)
	assert.Nil(t, trackCheckErr)
	assert.Equal(t, 2, tracked)
}
