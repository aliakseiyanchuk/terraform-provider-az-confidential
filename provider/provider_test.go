package provider

import (
	"context"
	"errors"
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

func Test_EnsureCanPlace_Errs_IfTrackerReturnsError(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, "obj-uuid").Return(false, errors.New("unit test track check error"))

	factory := &AZClientsFactoryImpl{
		LabelMatchRequirement: NoMatching,
		hashTacker:            hashTracker,
	}

	ctx := context.Background()
	dg := diag.Diagnostics{}

	factory.EnsureCanPlaceLabelledObjectAt(ctx, "obj-uuid", nil, "anything", nil, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "unit test track check error", dg[0].Detail())
	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Errs_IfTrackerReturnsObjectIsAlreadyTracked(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, "obj-uuid").Return(true, nil)

	factory := &AZClientsFactoryImpl{
		LabelMatchRequirement: NoMatching,
		hashTacker:            hashTracker,
	}

	ctx := context.Background()

	dg := diag.Diagnostics{}

	factory.EnsureCanPlaceLabelledObjectAt(ctx, "obj-uuid", nil, "secret", nil, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Potential attempt to copy confidential data detected: someone is trying to create a secret from ciphertext that was previously used", dg[0].Detail())
	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Errs_OnMismatchedTargetCoorLabel(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, "obj-uuid").Return(false, nil)

	factory := &AZClientsFactoryImpl{
		LabelMatchRequirement: TargetCoordinate,
		hashTacker:            hashTracker,
		ProviderLabels:        []string{"unit-testing"},
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

	factory.EnsureCanPlaceLabelledObjectAt(ctx, "obj-uuid", []string{expCoordinate.GetLabel()}, "secret", &reqCoordinate, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "The constraints embedded in the plaintext for this secret disallow placement with requested parameters", dg[0].Detail())
	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Ok_OnCoordinateLabelMatch(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, "obj-uuid").Return(false, nil)

	factory := &AZClientsFactoryImpl{
		LabelMatchRequirement: TargetCoordinate,
		hashTacker:            hashTracker,
		ProviderLabels:        []string{"unit-testing"},
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

	factory.EnsureCanPlaceLabelledObjectAt(ctx, "obj-uuid", []string{expCoordinate.GetLabel()}, "anything", &reqCoordinate, &dg)
	assert.False(t, dg.HasError())

	hashTracker.AssertExpectations(t)
}

func Test_EnsureCanPlace_Ok_OnProviderLabelsMatch(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, "obj-uuid").Return(false, nil)

	factory := &AZClientsFactoryImpl{
		LabelMatchRequirement: ProviderLabels,
		hashTacker:            hashTracker,
		ProviderLabels:        []string{"unit-testing", "foo-testing"},
	}

	ctx := context.Background()

	reqCoordinate := core.AzKeyVaultObjectCoordinate{
		VaultName: "vault-a",
		Type:      "secret",
		Name:      "obj-a",
	}

	dg := diag.Diagnostics{}

	factory.EnsureCanPlaceLabelledObjectAt(ctx,
		"obj-uuid",
		[]string{"test", "crazy-test", "foo-testing"},
		"unspecified resource",
		&reqCoordinate,
		&dg)
	assert.False(t, dg.HasError())

	hashTracker.AssertExpectations(t)
}

func Test_EnsureCanPlace_Errs_OnLabelMismatchForDataSource(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, "obj-uuid").Return(false, nil)

	modes := []LabelMatchRequirement{TargetCoordinate, ProviderLabels}

	for _, mode := range modes {
		factory := &AZClientsFactoryImpl{
			LabelMatchRequirement: mode,
			hashTacker:            hashTracker,
			ProviderLabels:        []string{"unit-testing"},
		}

		ctx := context.Background()

		dg := diag.Diagnostics{}
		factory.EnsureCanPlaceLabelledObjectAt(ctx,
			"obj-uuid",
			[]string{"actual-testing"},
			"unspecified-resource",
			nil,
			&dg)
		assert.True(t, dg.HasError())
		assert.Equal(t, "The constraints embedded in the ciphertext of this unspecified-resource disallow unwrapping the ciphertext by this provider", dg[0].Detail())
	}

	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_LabelMatchingRequirement_AsString(t *testing.T) {
	assert.Equal(t, "target-coordinate", TargetCoordinate.AsString())
	assert.Equal(t, "provider-labels", ProviderLabels.AsString())
	assert.Equal(t, "none", NoMatching.AsString())
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
	mdl.Labels = tfset

	converted := mdl.GetProviderLabels(context.Background())
	assert.True(t, len(converted) == 3)

	assert.Equal(t, "label_a", converted[0])
	assert.Equal(t, "label_b", converted[1])
	assert.Equal(t, "label_c", converted[2])
}

func Test_AZCPIM_GetLabelMatchingRequirement(t *testing.T) {
	mdl := AZConnectorProviderImplModel{
		LabelMatch: types.StringValue(TargetCoordinate.AsString()),
	}
	assert.Equal(t, TargetCoordinate, mdl.GetLabelMatchRequirement())

	mdl.LabelMatch = types.StringValue(ProviderLabels.AsString())
	assert.Equal(t, ProviderLabels, mdl.GetLabelMatchRequirement())

	mdl.LabelMatch = types.StringValue(NoMatching.AsString())
	assert.Equal(t, NoMatching, mdl.GetLabelMatchRequirement())
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
