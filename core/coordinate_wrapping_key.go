package core

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"strings"
)

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

func (w *WrappingKeyCoordinate) FillDefaults(ctx context.Context, client AzKeyClientAbstraction, diag *diag.Diagnostics) {
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
