package resources

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
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

func (m *AZClientsFactoryMock) GivenGetSecretClientWillReturnError(vaultAddr, msg string) {
	m.Mock.
		On("GetSecretsClient", vaultAddr).
		Return(nil, errors.New(msg))
}

func (m *AZClientsFactoryMock) GivenGetSecretClientWillReturn(vaultAddr string, cl core.AzSecretsClientAbstraction) {
	m.Mock.
		On("GetSecretsClient", vaultAddr).
		Return(cl, nil)
}

func (m *AZClientsFactoryMock) GivenIsObjectTrackingEnabled(enableOpt bool) {
	m.On("IsObjectTrackingEnabled").Return(enableOpt)
}

func (m *AZClientsFactoryMock) GivenGetSecretClientWillReturnNilClient(vaultAddr string) {
	m.Mock.
		On("GetSecretsClient", vaultAddr).
		Return(nil, nil)
}

func (m *AZClientsFactoryMock) GivenGetdestinationvaultobjectcoordinate(vaultAddr, objectType, objectName string) {
	m.Mock.
		On("GetDestinationVaultObjectCoordinate", mock.Anything, objectType).
		Return(core.AzKeyVaultObjectCoordinate{
			VaultName: vaultAddr,
			Name:      objectName,
			Type:      objectType,
		})
}

// ------------------
// Implementation methods

func (m *AZClientsFactoryMock) GetSecretsClient(vaultName string) (core.AzSecretsClientAbstraction, error) {
	rv := m.Mock.Called(vaultName)

	var rvCL core.AzSecretsClientAbstraction = nil
	if rv.Get(0) != nil {
		rvCL = rv.Get(0).(core.AzSecretsClientAbstraction)
	}

	return rvCL, rv.Error(1)
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

func (m *AZClientsFactoryMock) EnsureCanPlaceKeyVaultObjectAt(ctx context.Context, unwrappedPayload core.VersionedConfidentialData, targetCoord *core.AzKeyVaultObjectCoordinate, diagnostics *diag.Diagnostics) {
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

func (m *AZClientsFactoryMock) IsObjectTrackingEnabled() bool {
	rv := m.Mock.Called()
	return rv.Get(0).(bool)
}

func NewAzObjectNotFoundError() error {
	return errors.New("---------------\nRESPONSE 404: 404 Not Found")
}

// ----------------------------------------------------------------------------------------------------------------
// Az Secret Client

type SecretClientMock struct {
	core.AzSecretsClientAbstraction
	mock.Mock
}

func (m *SecretClientMock) GivenUpdateSecretPropertiesWillReturnError(secretName, secretVersion, errorMsg string) {
	var opt *azsecrets.UpdateSecretPropertiesOptions = nil

	m.On("UpdateSecretProperties", mock.Anything, secretName, secretVersion, mock.Anything, opt).
		Return(azsecrets.UpdateSecretPropertiesResponse{}, errors.New(errorMsg))
}

func (m *SecretClientMock) GivenUpdateSecretPropertiesWillSucceed(secretName, secretVersion, secretValue string) {
	var opt *azsecrets.UpdateSecretPropertiesOptions = nil

	resp := azsecrets.UpdateSecretPropertiesResponse{
		Secret: azsecrets.Secret{
			Value: to.Ptr(secretValue),
		},
	}

	m.On("UpdateSecretProperties", mock.Anything, secretName, secretVersion, mock.Anything, opt).
		Return(resp, nil)
}

func (m *SecretClientMock) GivenGetSecretWillReturnObjectNotFound(secretName, secretVersion string) {
	var opt *azsecrets.GetSecretOptions = nil
	m.On("GetSecret", mock.Anything, secretName, secretVersion, opt).
		Return(azsecrets.GetSecretResponse{}, NewAzObjectNotFoundError())
}

func (m *SecretClientMock) GivenGetSecretWillReturnError(secretName, secretVersion, errorMsg string) {
	var opt *azsecrets.GetSecretOptions = nil
	m.On("GetSecret", mock.Anything, secretName, secretVersion, opt).
		Return(azsecrets.GetSecretResponse{}, errors.New(errorMsg))
}

func (m *SecretClientMock) GivenGetSecret(secretName, secretVersion, value string) {
	var opt *azsecrets.GetSecretOptions = nil
	m.On("GetSecret", mock.Anything, secretName, secretVersion, opt).
		Return(azsecrets.GetSecretResponse{
			Secret: azsecrets.Secret{
				Value: to.Ptr(value),
			},
		}, nil)
}

func (m *SecretClientMock) GivenSetSecretWillReturnError(secretName, errorMessage string) {
	var params *azsecrets.SetSecretOptions = nil

	m.On("SetSecret", mock.Anything, secretName, mock.Anything, params).
		Return(azsecrets.SetSecretResponse{}, errors.New(errorMessage))
}

func (m *SecretClientMock) GivenSetSecret(secretName, secretContent string) {
	var options *azsecrets.SetSecretOptions = nil

	m.On("SetSecret", mock.Anything, secretName, mock.Anything, options).
		Return(azsecrets.SetSecretResponse{
			Secret: azsecrets.Secret{
				Value: to.Ptr(secretContent),
			},
		}, nil)
}

func (m *SecretClientMock) GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	args := m.Mock.Called(ctx, name, version, options)

	rvSecretState := args.Get(0).(azsecrets.GetSecretResponse)
	return rvSecretState, args.Error(1)
}

func (m *SecretClientMock) SetSecret(ctx context.Context, name string, param azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	args := m.Mock.Called(ctx, name, param, options)

	rvSecretState := args.Get(0).(azsecrets.SetSecretResponse)
	return rvSecretState, args.Error(1)
}

func (m *SecretClientMock) UpdateSecretProperties(ctx context.Context, name string, version string, parameters azsecrets.UpdateSecretPropertiesParameters, options *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error) {
	args := m.Mock.Called(ctx, name, version, parameters, options)
	return args.Get(0).(azsecrets.UpdateSecretPropertiesResponse), args.Error(1)
}
