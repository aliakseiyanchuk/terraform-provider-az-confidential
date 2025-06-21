// Copyright (c) HashiCorp, Inc.

package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"net/url"
	"strings"
)

type VersionedConfidentialData struct {
	Uuid       string
	Type       string
	BinaryData []byte
	StringData string
	Labels     []string
}

func (vcd *VersionedConfidentialData) PayloadAsB64Ptr() *string {
	if len(vcd.BinaryData) == 0 {
		return nil
	} else {
		out := base64.StdEncoding.EncodeToString(vcd.BinaryData)
		return &out
	}
}

// AZClientsFactory interface supplying Azure clients to various services.
type AZClientsFactory interface {
	GetSecretsClient(vaultName string) (*azsecrets.Client, error)
	GetKeysClient(vaultName string) (*azkeys.Client, error)
	GetCertificateClient(vaultName string) (*azcertificates.Client, error)

	// GetMergedWrappedKeyCoordinate get merged wrapping key coordinate providing
	// the values the parameter doesn't specify from teh provider's default settings
	GetMergedWrappingKeyCoordinate(ctx context.Context, param *WrappingKeyCoordinateModel, diag *diag.Diagnostics) WrappingKeyCoordinate

	// GetDestinationVaultObjectCoordinate GetDestinationSecretCoordinate retrieve the target coordinate where the
	//object needs to be created. This
	// method will append the default destination vault to the coordinate if a given model does not explicitly
	// specify this.
	GetDestinationVaultObjectCoordinate(coordinate AzKeyVaultObjectCoordinateModel) AzKeyVaultObjectCoordinate

	// EnsureCanPlace ensure that this object can be placed in the destination vault.
	// EnsureCanPlace ensure that this object can be placed in the destination vault.
	EnsureCanPlace(ctx context.Context, unwrappedPayload VersionedConfidentialData, targetCoord *AzKeyVaultObjectCoordinate, diagnostics *diag.Diagnostics)

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

func (c *AzKeyVaultObjectCoordinate) DefinesVaultName() bool {
	return len(c.VaultName) > 0
}

func (c *AzKeyVaultObjectCoordinate) GetLabel() string {
	return fmt.Sprintf("az-c-label://%s/%s@%s;", c.VaultName, c.Name, c.Type)
}

// AzKeyVaultPayload payload transferred to the vault coordinate
type AzKeyVaultPayload struct {
	AzKeyVaultObjectCoordinate
	Payload []byte
}

type WrappingKeyCoordinateModel struct {
	VaultName  types.String `tfsdk:"vault_name"`
	KeyName    types.String `tfsdk:"name"`
	KeyVersion types.String `tfsdk:"version"`
	Algorithm  types.String `tfsdk:"algorithm"`
}

func (w *WrappingKeyCoordinateModel) AsCoordinate() WrappingKeyCoordinate {
	return WrappingKeyCoordinate{
		VaultName:  w.VaultName.ValueString(),
		KeyName:    w.KeyName.ValueString(),
		KeyVersion: w.KeyVersion.ValueString(),
		Algorithm:  w.Algorithm.ValueString(),
	}
}

type WrappingKeyCoordinate struct {
	VaultName  string
	KeyName    string
	KeyVersion string
	Algorithm  string

	AzEncryptionAlg azkeys.EncryptionAlgorithm
}

func (w *WrappingKeyCoordinate) IsEmpty() bool {
	return len(w.VaultName) == 0 && len(w.KeyName) == 0 && len(w.KeyVersion) == 0 && len(w.Algorithm) == 0
}

func (w *WrappingKeyCoordinate) DefiesVaultName() bool {
	return len(w.VaultName) > 0
}

func (w *WrappingKeyCoordinate) DefiesKeyName() bool {
	return len(w.KeyName) > 0
}

func (w *WrappingKeyCoordinate) DefiesKeyVersion() bool {
	return len(w.KeyName) > 0
}

func (w *WrappingKeyCoordinate) DefiesKeyAlgorithm() bool {
	return len(w.Algorithm) > 0
}

func (w *WrappingKeyCoordinate) FillDefaults(ctx context.Context, client *azkeys.Client, diag *diag.Diagnostics) {
	if len(w.KeyVersion) == 0 {
		tflog.Trace(ctx, fmt.Sprintf("Attempting establish the latest version of the key %s in vault %s", w.KeyName, w.VaultName))

		if keyResp, readKeyErr := client.GetKey(ctx, w.KeyName, "", nil); readKeyErr != nil {
			diag.AddError("Was unable to retrieve the latest version of key", fmt.Sprintf("%s", readKeyErr.Error()))
			return
		} else {
			w.KeyVersion = keyResp.Key.KID.Version()
		}
	} else {
		if _, readKeyErr := client.GetKey(ctx, w.KeyName, w.KeyVersion, nil); readKeyErr != nil {
			diag.AddError("Was unable to retrieve the specified version of key", fmt.Sprintf("%s", readKeyErr.Error()))
			return
		}
	}

	azAlg, algDetectError := w.GetAzEncryptionAlgorithm()
	if algDetectError != nil {
		diag.AddError("Missing decryption algorithm", "The algorithm supplied doesn't match any supported decryption algorithms")
		return
	} else {
		w.AzEncryptionAlg = azAlg
	}
}

func (w *WrappingKeyCoordinate) GetAzEncryptionAlgorithm() (azkeys.EncryptionAlgorithm, error) {
	p_alg := w.GetAlgorithm()
	for _, alg := range azkeys.PossibleEncryptionAlgorithmValues() {
		if p_alg == string(alg) {
			return alg, nil
		}
	}

	return azkeys.EncryptionAlgorithmA128CBC, errors.New(fmt.Sprintf("Unknown algorithm: %s", w.Algorithm))
}

func (w *WrappingKeyCoordinate) GetAlgorithm() string {
	if len(w.Algorithm) > 0 {
		return w.Algorithm
	} else {
		return string(azkeys.EncryptionAlgorithmRSAOAEP256)
	}
}

func (w *WrappingKeyCoordinate) AddressesKey() bool {
	return len(w.VaultName) > 0 && len(w.KeyName) > 0
}

func (w *WrappingKeyCoordinate) Validate() diag.Diagnostics {
	var rv diag.Diagnostics

	if !w.AddressesKey() {
		summary := "Incomplete wrapping key address"

		detail := strings.Builder{}
		detail.WriteString("To unwrap a key, a at least vault name and wrapping key name must be supplied.")
		if len(w.VaultName) == 0 {
			detail.WriteString(" Vault name was not provided for this resource.")
		}
		if len(w.KeyName) == 0 {
			detail.WriteString(" Wrapping key name is not provided for this resource.")
		}

		rv = append(rv, diag.NewErrorDiagnostic(summary, detail.String()))
	}

	return rv
}

func mustMarshalJSON(v interface{}) string {
	if b, err := json.Marshal(v); err != nil {
		panic(err)
	} else {
		return string(b)
	}
}
