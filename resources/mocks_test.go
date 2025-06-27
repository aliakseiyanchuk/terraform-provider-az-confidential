package resources

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/mock"
)

type AZClientsFactoryMock struct {
	mock.Mock
}

func (m *AZClientsFactoryMock) GetSecretsClient(vaultName string) (*azsecrets.Client, error) {
	rv := m.Mock.Called(vaultName)
	return rv.Get(0).(*azsecrets.Client), rv.Error(1)
}

func (m *AZClientsFactoryMock) GetKeysClient(vaultName string) (*azkeys.Client, error) {
	rv := m.Mock.Called(vaultName)
	return rv.Get(0).(*azkeys.Client), rv.Error(1)
}

func (m *AZClientsFactoryMock) GetCertificateClient(vaultName string) (*azcertificates.Client, error) {
	rv := m.Mock.Called(vaultName)
	return rv.Get(0).(*azcertificates.Client), rv.Error(1)
}

func (m *AZClientsFactoryMock) GetMergedWrappingKeyCoordinate(ctx context.Context, param *core.WrappingKeyCoordinateModel, diag *diag.Diagnostics) core.WrappingKeyCoordinate {
	rv := m.Mock.Called(ctx, param, diag)
	return rv.Get(0).(core.WrappingKeyCoordinate)
}

func (m *AZClientsFactoryMock) EnsureCanPlace(ctx context.Context, unwrappedPayload core.VersionedConfidentialData, targetCoord *core.AzKeyVaultObjectCoordinate, diagnostics *diag.Diagnostics) {
	m.Mock.Called(ctx, unwrappedPayload, targetCoord, diagnostics)
}

func (m *AZClientsFactoryMock) GetDestinationVaultObjectCoordinate(coordinate core.AzKeyVaultObjectCoordinateModel, objType string) core.AzKeyVaultObjectCoordinate {
	rv := m.Mock.Called(coordinate, objType)
	return rv.Get(0).(core.AzKeyVaultObjectCoordinate)
}

func (m *AZClientsFactoryMock) IsObjectIdTracked(ctx context.Context, id string) (bool, error) {
	rv := m.Mock.Called(ctx, id)
	return rv.Get(0).(bool), rv.Error(1)
}

func (m *AZClientsFactoryMock) TrackObjectId(ctx context.Context, id string) error {
	rv := m.Mock.Called(ctx, id)
	return rv.Error(0)
}

func (m *AZClientsFactoryMock) GetDecrypterFor(ctx context.Context, coord core.WrappingKeyCoordinate) core.RSADecrypter {
	rv := m.Mock.Called(ctx, coord)
	return rv.Get(0).(core.RSADecrypter)
}
