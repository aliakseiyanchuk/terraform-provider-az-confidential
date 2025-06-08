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
	"strings"

	"github.com/google/uuid"
)

type VersionedConfidentialData struct {
	Uuid          string
	Type          string
	Payload       []byte
	StringPayload *string
	Labels        []string
}
type VersionedConfidentialDataJSONModel struct {
	Uuid          string   `json:"u"`
	Type          string   `json:"t"`
	BinaryPayload *string  `json:"b,omitempty"`
	StringPayload *string  `json:"s,omitempty"`
	Labels        []string `json:"l,omitempty"`
}

func UnwrapPayload(input []byte) (VersionedConfidentialData, error) {
	rv := VersionedConfidentialData{}

	jsonStr, gzipErr := GZipDecompress(input)
	if gzipErr != nil {
		return rv, gzipErr
	}

	mdl := VersionedConfidentialDataJSONModel{}

	if err := json.Unmarshal(jsonStr, &mdl); err != nil {
		return rv, err
	}

	rv.Uuid = mdl.Uuid
	rv.Type = mdl.Type
	rv.Labels = mdl.Labels

	if mdl.BinaryPayload != nil {
		if b, b64Err := base64.StdEncoding.DecodeString(*mdl.BinaryPayload); b64Err != nil {
			return rv, b64Err
		} else {
			rv.Payload = b
		}
	} else if mdl.StringPayload != nil {
		rv.StringPayload = mdl.StringPayload
		rv.Payload = []byte(*mdl.StringPayload)
	}

	return rv, nil
}

func WrapStringPayload(value, objType string, labels []string) []byte {
	rv := VersionedConfidentialDataJSONModel{
		Uuid:          uuid.New().String(),
		Type:          objType,
		StringPayload: &value,
		Labels:        labels,
	}

	jsonStr, _ := json.Marshal(&rv)
	return GZipCompress(jsonStr)
}

func WrapBinaryPayload(value []byte, objType string, labels []string) []byte {
	encStr := base64.StdEncoding.EncodeToString(value)

	rv := VersionedConfidentialDataJSONModel{
		Uuid:          uuid.New().String(),
		Type:          objType,
		BinaryPayload: &encStr,
		Labels:        labels,
	}

	jsonStr, _ := json.Marshal(rv)
	return GZipCompress(jsonStr)
}

// AZClientsFactory interface supplying Azure clients to various services.
type AZClientsFactory interface {
	GetSecretsClient(vaultName string) (*azsecrets.Client, error)
	GetKeysClient(vaultName string) (*azkeys.Client, error)
	GetCertificateClient(vaultName string) (*azcertificates.Client, error)

	// GetMergedWrappedKeyCoordinate get merged wrapping key coordinate providing
	// the values the parameter doesn't specify from teh provider's default settings
	GetMergedWrappingKeyCoordinate(ctx context.Context, param *WrappingKeyCoordinateModel, diag diag.Diagnostics) WrappingKeyCoordinate

	// GetDestinationVaultObjectCoordinate GetDestinationSecretCoordinate retrieve the target coordinate where the
	//object needs to be created. This
	// method will append the default destination vault to the coordinate if a given model does not explicitly
	// specify this.
	GetDestinationVaultObjectCoordinate(coordinate AzKeyVaultObjectCoordinateModel) AzKeyVaultObjectCoordinate

	GetOAEPLabelFor(d AzKeyVaultObjectCoordinate) []byte
	GetOAEPLabelForProvider() []byte

	IsObjectIdTracked(ctx context.Context, id string) (bool, error)
	TrackObjectId(ctx context.Context, id string) error
}

type AzResourceCoordinateModel struct {
	ResourceId types.String `tfsdk:"resource_id"`
}

type AzKeyVaultObjectVersionedCoordinate struct {
	AzKeyVaultObjectCoordinate
	Version string
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
	VaultName string
	Name      string
}

func (c *AzKeyVaultObjectCoordinate) DefinesVaultName() bool {
	return len(c.VaultName) > 0
}

func (c *AzKeyVaultObjectCoordinate) GetOAEPLabel() string {
	return fmt.Sprintf("oaep://%s/@%s;", c.VaultName, c.Name)
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

type WrappedPlainText struct {
	EncryptedText         []byte
	EncryptedContentKey   []byte
	WrappingKeyCoordinate WrappingKeyCoordinate
}

func (w *WrappedPlainText) Unwrap(ctx context.Context, factory AZClientsFactory) ([]byte, error) {
	client, err := factory.GetKeysClient(w.WrappingKeyCoordinate.VaultName)
	if err != nil {
		return nil, err
	}

	tflog.Trace(ctx, fmt.Sprintf("CEK length: %d", len(w.EncryptedContentKey)))

	if len(w.EncryptedContentKey) == 0 {
		tflog.Trace(ctx, "No CEK specified; performing direct decryption using vault")
		options := azkeys.KeyOperationParameters{
			Algorithm: &w.WrappingKeyCoordinate.AzEncryptionAlg,
			Value:     w.EncryptedText,
		}

		apiJson, apiJsonErr := options.MarshalJSON()
		tflog.Trace(ctx, fmt.Sprintf("Decryption params %s (conversion error: %s)", apiJson, apiJsonErr))
		decrResp, decrErr := client.Decrypt(ctx, w.WrappingKeyCoordinate.KeyName, w.WrappingKeyCoordinate.KeyVersion, options, nil)
		if decrErr != nil {
			tflog.Trace(ctx, fmt.Sprintf("Decryption error: %s", decrErr.Error()))

			return nil, decrErr
		}
		return decrResp.Result, nil
	} else {
		options := azkeys.KeyOperationParameters{
			Algorithm: &w.WrappingKeyCoordinate.AzEncryptionAlg,
			Value:     w.EncryptedText,
		}

		decrResp, decrErr := client.UnwrapKey(ctx, w.WrappingKeyCoordinate.KeyName, w.WrappingKeyCoordinate.KeyVersion, options, nil)
		if decrErr != nil {
			return nil, decrErr
		}

		// Decr response contains an AES decryption key that is additionally GZipped
		jsonBytes, gzipErr := GZipDecompress(decrResp.Result)
		if gzipErr != nil {
			return nil, gzipErr
		}

		var aesData AESData
		jsonErr := json.Unmarshal(jsonBytes, &aesData)
		if jsonErr != nil {
			return nil, jsonErr
		}

		plaintext, decrErr := AESDecrypt(w.EncryptedText, aesData)
		return plaintext, decrErr
	}
}

func (w *WrappingKeyCoordinate) FillDefaults(ctx context.Context, client *azkeys.Client, diag diag.Diagnostics) {
	if len(w.KeyVersion) == 0 {
		tflog.Trace(ctx, fmt.Sprintf("Attempting establish the latest version of the key %s in vault %s", w.KeyName, w.VaultName))

		if keyResp, readKeyErr := client.GetKey(ctx, w.KeyName, "", nil); readKeyErr != nil {
			diag.AddError("Was unable to retrieve the latest version of key", fmt.Sprintf("%s", readKeyErr.Error()))
			return
		} else {
			w.KeyVersion = keyResp.Key.KID.Version()
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

func (w *WrappingKeyCoordinate) Validate() []diag.Diagnostic {
	var rv []diag.Diagnostic

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
