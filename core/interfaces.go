package core

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"net/url"
	"strings"
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

type AzCertificateClientAbstraction interface {
	GetCertificate(ctx context.Context, name string, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error)
	ImportCertificate(ctx context.Context, name string, parameters azcertificates.ImportCertificateParameters, options *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error)
	UpdateCertificate(ctx context.Context, name string, version string, parameters azcertificates.UpdateCertificateParameters, options *azcertificates.UpdateCertificateOptions) (azcertificates.UpdateCertificateResponse, error)
}

// AZClientsFactory interface supplying Azure clients to various services.
type AZClientsFactory interface {
	GetSecretsClient(vaultName string) (AzSecretsClientAbstraction, error)
	GetKeysClient(vaultName string) (AzKeyClientAbstraction, error)
	GetCertificateClient(vaultName string) (AzCertificateClientAbstraction, error)

	// GetMergedWrappingKeyCoordinate get merged wrapping key coordinate providing
	// the values the parameter doesn't specify from the provider's default settings
	GetMergedWrappingKeyCoordinate(ctx context.Context, param *WrappingKeyCoordinateModel, diag *diag.Diagnostics) WrappingKeyCoordinate

	// GetDestinationVaultObjectCoordinate GetDestinationSecretCoordinate retrieve the target coordinate where the
	//object needs to be created. This
	// method will append the default destination vault to the coordinate if a given model does not explicitly
	// specify this.
	GetDestinationVaultObjectCoordinate(coordinate AzKeyVaultObjectCoordinateModel, objType string) AzKeyVaultObjectCoordinate

	// EnsureCanPlaceKeyVaultObjectAt ensures that this object can be placed in the destination vault.
	EnsureCanPlaceKeyVaultObjectAt(ctx context.Context, uuid string, labels []string, tfResourceType string, targetCoord *AzKeyVaultObjectCoordinate, diagnostics *diag.Diagnostics)

	IsObjectTrackingEnabled() bool
	IsObjectIdTracked(ctx context.Context, id string) (bool, error)
	TrackObjectId(ctx context.Context, id string) error

	GetDecrypterFor(ctx context.Context, coord WrappingKeyCoordinate) RSADecrypter
}

type AzResourceCoordinateModel struct {
	ResourceId types.String `tfsdk:"resource_id"`
}

type AzKeyVaultObjectVersionedCoordinate struct {
	AzKeyVaultObjectCoordinate
	Version string
}

func (c *AzKeyVaultObjectVersionedCoordinate) Clone() AzKeyVaultObjectVersionedCoordinate {
	return AzKeyVaultObjectVersionedCoordinate{
		AzKeyVaultObjectCoordinate: c.AzKeyVaultObjectCoordinate.Clone(),
		Version:                    c.Version,
	}
}

func (c *AzKeyVaultObjectVersionedCoordinate) SameAs(other AzKeyVaultObjectVersionedCoordinate) bool {
	return c.Version == other.Version &&
		c.AzKeyVaultObjectCoordinate.SameAs(other.AzKeyVaultObjectCoordinate)
}

func (c *AzKeyVaultObjectVersionedCoordinate) FromId(id string) error {
	if parsedURL, err := url.Parse(id); err != nil {
		return err
	} else {
		c.idHostName = parsedURL.Host
		c.VaultName = strings.Split(parsedURL.Host, ".")[0]
		parsedPath := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")

		if len(parsedPath) != 3 {
			return fmt.Errorf("invalid reosurce path: %s (id=%s)", parsedURL.Path, id)
		}

		c.Type = parsedPath[0]
		c.Name = parsedPath[1]
		c.Version = parsedPath[2]

		return nil
	}
}

func (c *AzKeyVaultObjectVersionedCoordinate) VersionlessId() string {
	return fmt.Sprintf("https://%s/%s/%s", c.idHostName, c.Type, c.Name)
}

type AzKeyVaultObjectVersionedCoordinateModel struct {
	AzResourceCoordinateModel
	AzKeyVaultObjectCoordinateModel

	Version types.String `tfsdk:"version"`
}

func (mdl *AzKeyVaultObjectVersionedCoordinateModel) IsEmpty() bool {
	return mdl.Version.IsNull() && mdl.Name.IsNull() && mdl.VaultName.IsNull() && mdl.ResourceId.IsNull()
}

// AzKeyVaultObjectCoordinate computed runtime coordinate
type AzKeyVaultObjectCoordinate struct {
	VaultName  string
	idHostName string // Name of the host as fully specified
	Name       string
	Type       string
}

func (c *AzKeyVaultObjectCoordinate) AsString() string {
	return fmt.Sprintf("v:=%s/t=%s/n=%s", c.VaultName, c.Type, c.Name)
}

func (c *AzKeyVaultObjectCoordinate) Clone() AzKeyVaultObjectCoordinate {
	return AzKeyVaultObjectCoordinate{
		VaultName:  c.VaultName,
		idHostName: c.idHostName,
		Name:       c.Name,
		Type:       c.Type,
	}
}

func (c *AzKeyVaultObjectCoordinate) SameAs(other AzKeyVaultObjectCoordinate) bool {
	return c.VaultName == other.VaultName &&
		c.Name == other.Name &&
		c.Type == other.Type
}

func (c *AzKeyVaultObjectCoordinate) DefinesVaultName() bool {
	return len(c.VaultName) > 0
}

func (c *AzKeyVaultObjectCoordinate) GetLabel() string {
	return fmt.Sprintf("az-c-label://%s/%s@%s;", c.VaultName, c.Name, c.Type)
}
