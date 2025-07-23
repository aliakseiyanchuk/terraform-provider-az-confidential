package keyvault

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

func (m *AZClientsFactoryMock) GetAzSubscription(v string) (string, error) {
	args := m.Called(v)
	return args.String(0), args.Error(1)
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

func (m *AZClientsFactoryMock) GivenGetCertificatesClientWillReturnError(vaultAddr, msg string) {
	m.Mock.
		On("GetCertificateClient", vaultAddr).
		Return(nil, errors.New(msg))
}

func (m *AZClientsFactoryMock) GivenGetCertificatesClientWillReturn(vaultAddr string, cl core.AzCertificateClientAbstraction) {
	m.Mock.
		On("GetCertificateClient", vaultAddr).
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

func (m *AZClientsFactoryMock) GivenGetDestinationVaultObjectCoordinate(vaultAddr, objectType, objectName string) {
	m.Mock.
		On("GetDestinationVaultObjectCoordinate", mock.Anything, objectType).
		Return(core.AzKeyVaultObjectCoordinate{
			VaultName: vaultAddr,
			Name:      objectName,
			Type:      objectType,
		})
}

func (m *AZClientsFactoryMock) GivenGetKeysClientWillReturnError(vaultAddr, msg string) {
	m.Mock.
		On("GetKeysClient", vaultAddr).
		Return(nil, errors.New(msg))
}

func (m *AZClientsFactoryMock) GivenGetKeysClientWillReturnNilClient(vaultAddr string) {
	m.Mock.
		On("GetKeysClient", vaultAddr).
		Return(nil, nil)
}

func (m *AZClientsFactoryMock) GivenGetCertificatesClientWillReturnNilClient(vaultAddr string) {
	m.Mock.
		On("GetCertificateClient", vaultAddr).
		Return(nil, nil)
}

func (m *AZClientsFactoryMock) GivenGetKeysClientWillReturn(vaultAddr string, cl core.AzKeyClientAbstraction) {
	m.Mock.
		On("GetKeysClient", vaultAddr).
		Return(cl, nil)
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

func (m *AZClientsFactoryMock) GetKeysClient(vaultName string) (core.AzKeyClientAbstraction, error) {
	rv := m.Mock.Called(vaultName)

	var rvCl core.AzKeyClientAbstraction = nil
	if rv.Get(0) != nil {
		rvCl = rv.Get(0).(core.AzKeyClientAbstraction)
	}
	return rvCl, rv.Error(1)
}

func (m *AZClientsFactoryMock) GetCertificateClient(vaultName string) (core.AzCertificateClientAbstraction, error) {
	rv := m.Mock.Called(vaultName)

	var rvCl core.AzCertificateClientAbstraction = nil
	if rv.Get(0) != nil {
		rvCl = rv.Get(0).(core.AzCertificateClientAbstraction)
	}

	return rvCl, rv.Error(1)
}

func (m *AZClientsFactoryMock) GetMergedWrappingKeyCoordinate(ctx context.Context, param *core.WrappingKeyCoordinateModel, diag *diag.Diagnostics) core.WrappingKeyCoordinate {
	rv := m.Mock.Called(ctx, param, diag)
	return rv.Get(0).(core.WrappingKeyCoordinate)
}

func (m *AZClientsFactoryMock) EnsureCanPlaceLabelledObjectAt(ctx context.Context, pc []core.ProviderConstraint, pl []core.PlacementConstraint, tfResourceType string, targetCoord core.LabelledObject, diagnostics *diag.Diagnostics) {
	m.Mock.Called(ctx, pc, pl, tfResourceType, targetCoord, diagnostics)
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

func (m *AZClientsFactoryMock) GetTackedObjectUses(ctx context.Context, id string) (int, error) {
	rv := m.Mock.Called(ctx, id)
	return rv.Get(0).(int), rv.Error(1)
}

func (m *AZClientsFactoryMock) GetDecrypterFor(ctx context.Context, coord core.WrappingKeyCoordinate) core.RSADecrypter {
	rv := m.Mock.Called(ctx, coord)
	return rv.Get(0).(core.RSADecrypter)
}

func (m *AZClientsFactoryMock) IsObjectTrackingEnabled() bool {
	rv := m.Mock.Called()
	return rv.Get(0).(bool)
}

func (m *AZClientsFactoryMock) GetApimSubscriptionClient(subscriptionId string) (core.ApimSubscriptionClientAbstraction, error) {
	rv := m.Mock.Called(subscriptionId)
	return rv.Get(0).(core.ApimSubscriptionClientAbstraction), rv.Error(1)
}

func (m *AZClientsFactoryMock) GetApimNamedValueClient(subscriptionId string) (core.ApimNamedValueClientAbstraction, error) {
	rv := m.Mock.Called(subscriptionId)
	return rv.Get(0).(core.ApimNamedValueClientAbstraction), rv.Error(1)
}

func MockedAzObjectNotFoundError() error {
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
		Return(azsecrets.GetSecretResponse{}, MockedAzObjectNotFoundError())
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

type KeysClientMock struct {
	mock.Mock
}

func (k *KeysClientMock) GivenUpdateKeyReturnsError(keyName, keyVersion, errorMessage string) {
	var opts *azkeys.UpdateKeyOptions = nil

	k.On("UpdateKey", mock.Anything, keyName, keyVersion, mock.Anything, opts).
		Return(azkeys.UpdateKeyResponse{}, errors.New(errorMessage))
}

func (k *KeysClientMock) GivenUpdateKey(keyName, keyVersion string) {
	var opts *azkeys.UpdateKeyOptions = nil

	k.On("UpdateKey", mock.Anything, keyName, keyVersion, mock.Anything, opts).
		Return(azkeys.UpdateKeyResponse{}, nil)
}

func (k *KeysClientMock) GivenImportKeyReturnsError(keyName, errorMessage string) {
	var opts *azkeys.ImportKeyOptions = nil

	k.On("ImportKey", mock.Anything, keyName, mock.Anything, opts).
		Return(azkeys.ImportKeyResponse{}, errors.New(errorMessage))
}

func (k *KeysClientMock) GivenImportKey(keyName string) {
	var opts *azkeys.ImportKeyOptions = nil

	k.On("ImportKey", mock.Anything, keyName, mock.Anything, opts).
		Return(azkeys.ImportKeyResponse{}, nil)
}

func (k *KeysClientMock) GivenGetKeyReturnsError(name, version, errorMsg string) {
	var options *azkeys.GetKeyOptions = nil
	k.On("GetKey", mock.Anything, name, version, options).
		Return(azkeys.GetKeyResponse{}, errors.New(errorMsg))
}

func (k *KeysClientMock) GivenGetKey(name, version string) {
	var options *azkeys.GetKeyOptions = nil
	k.On("GetKey", mock.Anything, name, version, options).
		Return(azkeys.GetKeyResponse{
			KeyBundle: azkeys.KeyBundle{
				Managed: to.Ptr(false),
			},
		}, nil)
}

func (k *KeysClientMock) GivenGetKeyReturnsObjectNotFound(name, version string) {
	var options *azkeys.GetKeyOptions = nil
	k.On("GetKey", mock.Anything, name, version, options).
		Return(azkeys.GetKeyResponse{}, MockedAzObjectNotFoundError())
}

func (k *KeysClientMock) ImportKey(ctx context.Context, name string, parameters azkeys.ImportKeyParameters, options *azkeys.ImportKeyOptions) (azkeys.ImportKeyResponse, error) {
	args := k.Called(ctx, name, parameters, options)
	return args.Get(0).(azkeys.ImportKeyResponse), args.Error(1)
}

func (k *KeysClientMock) Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	args := k.Called(ctx, name, version, parameters, options)
	return args.Get(0).(azkeys.DecryptResponse), args.Error(1)
}

func (k *KeysClientMock) UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	args := k.Called(ctx, name, version, parameters, options)
	return args.Get(0).(azkeys.UpdateKeyResponse), args.Error(1)
}

func (k *KeysClientMock) GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	args := k.Called(ctx, name, version, options)
	return args.Get(0).(azkeys.GetKeyResponse), args.Error(1)
}

type CertificateClientMock struct {
	mock.Mock
}

func (c *CertificateClientMock) GivenGetCertificateReturnsObjectNotFound(name, version string) {
	var opts *azcertificates.GetCertificateOptions = nil
	c.On("GetCertificate", mock.Anything, name, version, opts).
		Return(azcertificates.GetCertificateResponse{}, MockedAzObjectNotFoundError())
}

func (c *CertificateClientMock) GivenGetCertificateErrs(name, version, errorMessage string) {
	var opts *azcertificates.GetCertificateOptions = nil
	c.On("GetCertificate", mock.Anything, name, version, opts).
		Return(azcertificates.GetCertificateResponse{}, errors.New(errorMessage))
}

func (c *CertificateClientMock) GivenImportCertificateErrs(name, errorMessage string) {
	var opts *azcertificates.ImportCertificateOptions = nil
	c.On("ImportCertificate", mock.Anything, name, mock.Anything, opts).
		Return(azcertificates.ImportCertificateResponse{}, errors.New(errorMessage))
}

func (c *CertificateClientMock) GivenImportCertificate(name string) {
	var opts *azcertificates.ImportCertificateOptions = nil
	c.On("ImportCertificate", mock.Anything, name, mock.Anything, opts).
		Return(azcertificates.ImportCertificateResponse{}, nil)
}

func (c *CertificateClientMock) GivenGetCertificate(name, version string) {
	var opts *azcertificates.GetCertificateOptions = nil
	c.On("GetCertificate", mock.Anything, name, version, opts).
		Return(azcertificates.GetCertificateResponse{}, nil)
}

func (c *CertificateClientMock) GivenUpdateCertificate(name, version string) {
	var opts *azcertificates.UpdateCertificateOptions = nil
	c.On("UpdateCertificate", mock.Anything, name, version, mock.Anything, opts).
		Return(azcertificates.UpdateCertificateResponse{}, nil)
}

func (c *CertificateClientMock) GivenUpdateCertificateErrs(name, version string, errorMessage string) {
	var opts *azcertificates.UpdateCertificateOptions = nil
	c.On("UpdateCertificate", mock.Anything, name, version, mock.Anything, opts).
		Return(azcertificates.UpdateCertificateResponse{}, errors.New(errorMessage))
}

func (c *CertificateClientMock) GetCertificate(ctx context.Context, name string, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error) {
	args := c.Called(ctx, name, version, options)
	return args.Get(0).(azcertificates.GetCertificateResponse), args.Error(1)
}

func (c *CertificateClientMock) ImportCertificate(ctx context.Context, name string, parameters azcertificates.ImportCertificateParameters, options *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error) {
	args := c.Called(ctx, name, parameters, options)
	return args.Get(0).(azcertificates.ImportCertificateResponse), args.Error(1)
}

func (c *CertificateClientMock) UpdateCertificate(ctx context.Context, name string, version string, parameters azcertificates.UpdateCertificateParameters, options *azcertificates.UpdateCertificateOptions) (azcertificates.UpdateCertificateResponse, error) {
	args := c.Called(ctx, name, version, parameters, options)
	return args.Get(0).(azcertificates.UpdateCertificateResponse), args.Error(1)
}
