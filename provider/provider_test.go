package provider

import (
	"context"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	tfprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func Test_AZPI_ProviderSchemaWillLoad(t *testing.T) {
	p := New("unittest")()
	req := tfprovider.SchemaRequest{}
	resp := tfprovider.SchemaResponse{}
	p.Schema(nil, req, &resp)

	assert.NotNil(t, resp.Schema)
	assert.False(t, resp.Diagnostics.HasError())
}

func Test_AZPI_WillReturnDataSources(t *testing.T) {
	p := New("unittest")()
	assert.NotNil(t, p.DataSources(context.Background()))
}

func Test_AZPI_WillReturnResources(t *testing.T) {
	p := New("unittest")()
	assert.NotNil(t, p.Resources(context.Background()))
}

func Test_AZPI_WillReturnMetadata(t *testing.T) {
	p := New("unittest")()

	req := tfprovider.MetadataRequest{}
	resp := tfprovider.MetadataResponse{}
	p.Metadata(nil, req, &resp)

	assert.Equal(t, "az-confidential", resp.TypeName)
	assert.Equal(t, "unittest", resp.Version)
}

type HashTrackerMock struct {
	mock.Mock
}

func (m *HashTrackerMock) IsObjectIdTracked(ctx context.Context, id string) (bool, error) {
	args := m.Called(ctx, id)
	return args.Bool(0), args.Error(1)
}

// TrackObjectId Track object Id in the memory of seeing objects
func (m *HashTrackerMock) TrackObjectId(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func Test_EnsureCanPlace_Errs_OnMismatchedTargetCoorLabel(t *testing.T) {
	factory := &AZClientsFactoryImpl{
		ProviderLabels: []string{"unit-testing"},
	}

	ctx := context.Background()

	expCoordinate := core.AzKeyVaultObjectCoordinate{
		VaultName: "vault-a",
		Type:      "secret",
		Name:      "obj-a",
	}

	reqCoordinate := core.AzKeyVaultObjectCoordinate{
		VaultName: "vault-a",
		Type:      "secret",
		Name:      "obj-b",
	}

	dg := diag.Diagnostics{}

	factory.EnsureCanPlaceLabelledObjectAt(ctx, nil, []core.PlacementConstraint{expCoordinate.GetPlacementConstraint()}, "secret", &reqCoordinate, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t,
		"The constraints embedded into the ciphertext disallow placement of this secret into the specified destination. More information is not given for security reasons. Re-encrypt the ciphertext with correct placement constraints.",
		dg[0].Detail())
}

func Test_EnsureCanPlace_Ok_OnCoordinateLabelMatch(t *testing.T) {
	factory := &AZClientsFactoryImpl{
		ProviderLabels: []string{"unit-testing"},
	}

	ctx := context.Background()

	expCoordinate := core.AzKeyVaultObjectCoordinate{
		VaultName: "vault-a",
		Type:      "secret",
		Name:      "obj-a",
	}

	reqCoordinate := core.AzKeyVaultObjectCoordinate{
		VaultName: "vault-a",
		Type:      "secret",
		Name:      "obj-a",
	}

	dg := diag.Diagnostics{}

	factory.EnsureCanPlaceLabelledObjectAt(ctx,
		nil,
		[]core.PlacementConstraint{expCoordinate.GetPlacementConstraint()},
		"anything",
		&reqCoordinate,
		&dg)
	assert.False(t, dg.HasError())

}

func Test_EnsureCanPlace_Ok_OnProviderLabelsMatch(t *testing.T) {
	factory := &AZClientsFactoryImpl{
		ProviderLabels: []string{"unit-testing", "foo-testing"},
	}

	ctx := context.Background()

	reqCoordinate := core.AzKeyVaultObjectCoordinate{
		VaultName: "vault-a",
		Type:      "secret",
		Name:      "obj-a",
	}

	dg := diag.Diagnostics{}

	factory.EnsureCanPlaceLabelledObjectAt(ctx,
		[]core.ProviderConstraint{"test", "crazy-test", "foo-testing"},
		nil,
		"unspecified resource",
		&reqCoordinate,
		&dg)
	assert.False(t, dg.HasError())

}

func Test_EnsureCanPlace_Errs_OnLabelMismatchForDataSource(t *testing.T) {
	factory := &AZClientsFactoryImpl{
		ProviderLabels: []string{"unit-testing"},
	}

	ctx := context.Background()

	dg := diag.Diagnostics{}
	factory.EnsureCanPlaceLabelledObjectAt(ctx,
		[]core.ProviderConstraint{"actual-testing"},
		nil,
		"unspecified-resource",
		nil,
		&dg)
	assert.True(t, dg.HasError())
	assert.Equal(t,
		"The constraints embedded into the ciphertext disallow placement of this unspecified-resource by this provider. More information is not given for security reasons. Re-encrypt the ciphertext with correct provider constraints.",
		dg[0].Detail())
}

func Test_AZCPIM_GetProviderLabels(t *testing.T) {
	mdl := AZConnectorProviderImplModel{}

	values := []attr.Value{
		types.StringValue("label_a"),
		types.StringValue("label_b"),
		types.StringValue("label_c"),
	}

	tfset, err := types.SetValue(types.StringType, values)
	assert.Nil(t, err)
	mdl.Constraints = tfset

	converted := mdl.GetProviderLabels(context.Background())
	assert.True(t, len(converted) == 3)

	assert.Equal(t, "label_a", converted[0])
	assert.Equal(t, "label_b", converted[1])
	assert.Equal(t, "label_c", converted[2])
}

func Test_AZCPIM_SpecifiesCredentialParameters(t *testing.T) {
	mdl := AZConnectorProviderImplModel{}
	assert.False(t, mdl.SpecifiesCredentialParameters())

	mdl = AZConnectorProviderImplModel{
		TenantID:       types.StringValue("tenant-id"),
		ClientSecret:   types.StringValue("client-secret"),
		ClientID:       types.StringValue("client-id"),
		SubscriptionID: types.StringValue("subscription-id"),
	}
	assert.True(t, mdl.SpecifiesCredentialParameters())
}
