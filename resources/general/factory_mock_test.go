package general

import (
	"context"
	"errors"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/mock"
)

type FactoryMock struct {
	core.AZClientsFactory
	mock.Mock
}

func (m *FactoryMock) EnsureCanPlaceLabelledObjectAt(ctx context.Context, providerConstraint []core.ProviderConstraint, placementConstraint []core.PlacementConstraint, tfResourceType string, targetCoord core.LabelledObject, diagnostics *diag.Diagnostics) {
	m.Called(ctx, providerConstraint, placementConstraint, tfResourceType, targetCoord, diagnostics)
}

func (m *FactoryMock) IsObjectTrackingEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *FactoryMock) GivenIsObjectTrackingEnabled(how bool) {
	m.On("IsObjectTrackingEnabled").Return(how)
}

func (m *FactoryMock) GetTackedObjectUses(ctx context.Context, id string) (int, error) {
	args := m.Called(ctx, id)
	return args.Int(0), args.Error(1)
}

func (m *FactoryMock) GivenGetTackedObjectUsesErrs(uuid, msg string) {
	m.On("GetTackedObjectUses", mock.Anything, uuid).
		Return(0, errors.New(msg))
}

func (m *FactoryMock) GivenGetTackedObjectUses(uuid string, n int) {
	m.On("GetTackedObjectUses", mock.Anything, uuid).
		Return(n, nil)
}

func (m *FactoryMock) GivenEnsureCanPlaceLabelledObject(objType string) {
	m.On("EnsureCanPlaceLabelledObjectAt",
		mock.Anything, // context
		mock.Anything, // provider constraints
		mock.Anything, // placement constraints
		objType,
		nil,           // target coordinate
		mock.Anything, // diagnosis
	).Once()
}

func (m *FactoryMock) GivenEnsureCanPlaceLabelledObjectAtRaisesError(objType string) {
	m.On("EnsureCanPlaceLabelledObjectAt",
		mock.Anything, // context
		mock.Anything, // provider constraints
		mock.Anything, // placement constraints
		objType,
		nil,           // target coordinate
		mock.Anything, // diagnosis
	).Run(
		func(args mock.Arguments) {
			dg := args.Get(5).(*diag.Diagnostics)
			dg.AddError("Can't place object unit test error", "unit test error detail")
		},
	)
}
