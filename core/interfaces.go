package core

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AzSecretsClientAbstraction interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	UpdateSecretProperties(ctx context.Context, name string, version string, parameters azsecrets.UpdateSecretPropertiesParameters, options *azsecrets.UpdateSecretPropertiesOptions) (azsecrets.UpdateSecretPropertiesResponse, error)
}

type AzKeyClientAbstraction interface {
	ImportKey(ctx context.Context, name string, parameters azkeys.ImportKeyParameters, options *azkeys.ImportKeyOptions) (azkeys.ImportKeyResponse, error)
	Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
	UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
}

type ApimNamedValueClientAbstraction interface {
	Get(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, options *armapimanagement.NamedValueClientGetOptions) (armapimanagement.NamedValueClientGetResponse, error)
	ListValue(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, options *armapimanagement.NamedValueClientListValueOptions) (armapimanagement.NamedValueClientListValueResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, options *armapimanagement.NamedValueClientDeleteOptions) (armapimanagement.NamedValueClientDeleteResponse, error)
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, parameters armapimanagement.NamedValueCreateContract, options *armapimanagement.NamedValueClientBeginCreateOrUpdateOptions) (PollerAbstraction[armapimanagement.NamedValueClientCreateOrUpdateResponse], error)
	BeginUpdate(ctx context.Context, resourceGroupName string, serviceName string, namedValueID string, ifMatch string, parameters armapimanagement.NamedValueUpdateParameters, options *armapimanagement.NamedValueClientBeginUpdateOptions) (PollerAbstraction[armapimanagement.NamedValueClientUpdateResponse], error)
}

type PollerAbstraction[T any] interface {
	PollUntilDone(ctx context.Context, options *runtime.PollUntilDoneOptions) (res T, err error)
}

type ApimSubscriptionClientAbstraction interface {
	Get(ctx context.Context, resourceGroupName string, serviceName string, sid string, options *armapimanagement.SubscriptionClientGetOptions) (armapimanagement.SubscriptionClientGetResponse, error)
	ListSecrets(ctx context.Context, resourceGroupName string, serviceName string, sid string, options *armapimanagement.SubscriptionClientListSecretsOptions) (armapimanagement.SubscriptionClientListSecretsResponse, error)
	CreateOrUpdate(ctx context.Context, resourceGroupName string, serviceName string, sid string, parameters armapimanagement.SubscriptionCreateParameters, options *armapimanagement.SubscriptionClientCreateOrUpdateOptions) (armapimanagement.SubscriptionClientCreateOrUpdateResponse, error)
	Update(ctx context.Context, resourceGroupName string, serviceName string, sid string, ifMatch string, parameters armapimanagement.SubscriptionUpdateParameters, options *armapimanagement.SubscriptionClientUpdateOptions) (armapimanagement.SubscriptionClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, serviceName string, sid string, ifMatch string, options *armapimanagement.SubscriptionClientDeleteOptions) (armapimanagement.SubscriptionClientDeleteResponse, error)
}

type AzCertificateClientAbstraction interface {
	GetCertificate(ctx context.Context, name string, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error)
	ImportCertificate(ctx context.Context, name string, parameters azcertificates.ImportCertificateParameters, options *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error)
	UpdateCertificate(ctx context.Context, name string, version string, parameters azcertificates.UpdateCertificateParameters, options *azcertificates.UpdateCertificateOptions) (azcertificates.UpdateCertificateResponse, error)
}

// AZClientsFactory interface supplying Azure clients to various services.
type AZClientsFactory interface {
	GetSecretsClient(vaultName string) (AzSecretsClientAbstraction, error)
	GetKeysClient(vaultName string) (AzKeyClientAbstraction, error)
	GetApimSubscriptionClient(subscriptionId string) (ApimSubscriptionClientAbstraction, error)
	GetApimNamedValueClient(subscriptionId string) (ApimNamedValueClientAbstraction, error)
	GetCertificateClient(vaultName string) (AzCertificateClientAbstraction, error)

	// GetMergedWrappingKeyCoordinate get merged wrapping key coordinate providing
	// the values the parameter doesn't specify from the provider's default settings
	GetMergedWrappingKeyCoordinate(ctx context.Context, param *WrappingKeyCoordinateModel, diag *diag.Diagnostics) WrappingKeyCoordinate

	// GetDestinationVaultObjectCoordinate GetDestinationSecretCoordinate retrieve the target coordinate where the
	//object needs to be created. This
	// method will append the default destination vault to the coordinate if a given model does not explicitly
	// specify this.
	GetDestinationVaultObjectCoordinate(coordinate AzKeyVaultObjectCoordinateModel, objType string) AzKeyVaultObjectCoordinate

	// GetAzSubscription returns the Azure subscription. The return value is a value of v if it is a non-empty
	// string, otherwise it is a default Azure subscription configured by this provider. An error is returned
	// when neither input nor provider default yield a valid subscription.
	GetAzSubscription(v string) (string, error)

	// EnsureCanPlaceLabelledObjectAt ensures that objected originating from the ciphertext identified by uuid
	// and ciphertext bearing labels can be placed at the target coordinate. The logic of this method is as follows:
	// - if the provider has to ensure strict labeling match, then one of the labels associated with ciphertext must be
	//   equal to the value the target coordinate provides
	// - if the provider has to ensure provider-level matching, then at least one ciphertext label must match the one
	//   assigned to the provider
	// - where disabled, the check always succeeds.
	EnsureCanPlaceLabelledObjectAt(ctx context.Context, uuid string, labels []string, tfResourceType string, targetCoord LabelledObject, diagnostics *diag.Diagnostics)

	IsObjectTrackingEnabled() bool
	IsObjectIdTracked(ctx context.Context, id string) (bool, error)
	TrackObjectId(ctx context.Context, id string) error

	GetDecrypterFor(ctx context.Context, coord WrappingKeyCoordinate) RSADecrypter
}

// TODO Probaaby this model needs to be deleted as not useful
type AzResourceCoordinateModel struct {
	ResourceId types.String `tfsdk:"resource_id"`
}

type LabelledObject interface {
	GetLabel() string
}
