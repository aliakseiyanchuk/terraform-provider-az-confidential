package provider

import (
	"context"
	"errors"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

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
	hashTracker.On("IsObjectIdTracked", mock.Anything, mock.Anything).Return(false, errors.New("unit test track check error"))

	factory := &AZClientsFactoryImpl{
		LabelMatchRequirement: NoMatching,
		hashTacker:            hashTracker,
	}

	ctx := context.Background()
	v := core.VersionedConfidentialData{}
	dg := diag.Diagnostics{}

	factory.EnsureCanPlace(ctx, v, nil, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "unit test track check error", dg[0].Detail())
	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Errs_IfTrackerReturnsObjectIsAlreadyTracked(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, mock.Anything).Return(true, nil)

	factory := &AZClientsFactoryImpl{
		LabelMatchRequirement: NoMatching,
		hashTacker:            hashTracker,
	}

	ctx := context.Background()
	v := core.VersionedConfidentialData{}
	dg := diag.Diagnostics{}

	factory.EnsureCanPlace(ctx, v, nil, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Potential malfeasance detected: someone is trying to create a secret from records that were previously used", dg[0].Detail())
	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Errs_OnMismatchedTargetCoorLabel(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, mock.Anything).Return(false, nil)

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

	v := core.VersionedConfidentialData{
		Type: "secret",
		Labels: []string{
			expCoordinate.GetLabel(),
		},
	}
	dg := diag.Diagnostics{}

	factory.EnsureCanPlace(ctx, v, &reqCoordinate, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "This secret cannot be unwrapped into secret in vault vault-a/obj-b", dg[0].Detail())
	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Ok_OnCoordinateLabelMatch(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, mock.Anything).Return(false, nil)

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

	v := core.VersionedConfidentialData{
		Type: "secret",
		Labels: []string{
			expCoordinate.GetLabel(),
		},
	}
	dg := diag.Diagnostics{}

	factory.EnsureCanPlace(ctx, v, &reqCoordinate, &dg)
	assert.False(t, dg.HasError())

	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Ok_OnProviderLabelsMatch(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, mock.Anything).Return(false, nil)

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

	v := core.VersionedConfidentialData{
		Type: "secret",
		Labels: []string{
			"test", "crazy-test", "foo-testing",
		},
	}
	dg := diag.Diagnostics{}

	factory.EnsureCanPlace(ctx, v, &reqCoordinate, &dg)
	assert.False(t, dg.HasError())

	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_EnsureCanPlace_Errs_OnLabelMismatchForDataSource(t *testing.T) {
	hashTracker := &HashTrackerMock{}
	hashTracker.On("IsObjectIdTracked", mock.Anything, mock.Anything).Return(false, nil)

	modes := []LabelMatchRequirement{TargetCoordinate, ProviderLabels}

	for _, mode := range modes {
		factory := &AZClientsFactoryImpl{
			LabelMatchRequirement: mode,
			hashTacker:            hashTracker,
			ProviderLabels:        []string{"unit-testing"},
		}

		ctx := context.Background()

		v := core.VersionedConfidentialData{
			Type: "password",
			Labels: []string{
				"actual-testing",
			},
		}
		dg := diag.Diagnostics{}

		factory.EnsureCanPlace(ctx, v, nil, &dg)
		assert.True(t, dg.HasError())
		assert.Equal(t, "This password cannot be unwrapped by this provider", dg[0].Detail())
	}

	assert.True(t, hashTracker.AssertExpectations(t))
}

func Test_AZCFI_GetMergedWrappingKeyCoordinate(t *testing.T) {

}
