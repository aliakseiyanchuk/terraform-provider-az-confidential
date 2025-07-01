package resources

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/crypto/ssh"
	"math/big"
)

type ConfidentialKeyModel struct {
	WrappedAzKeyVaultObjectConfidentialMaterialModel

	HSM            types.Bool                           `tfsdk:"hsm"`
	DestinationKey core.AzKeyVaultObjectCoordinateModel `tfsdk:"destination_key"`
	KeyOperations  types.Set                            `tfsdk:"key_opts"`

	KeyVersion types.String `tfsdk:"key_version"`

	PublicKeyPem     types.String `tfsdk:"public_key_pem"`
	PublicKeyOpenSSH types.String `tfsdk:"public_key_openssh"`
}

func (cm *ConfidentialKeyModel) GetKeyOperations() []*azkeys.KeyOperation {
	var rv []*azkeys.KeyOperation

	elements := make([]types.String, 0, len(cm.KeyOperations.Elements()))

	for _, val := range elements {
		strVal := val.ValueString()

		var selectedKeyOp azkeys.KeyOperation
		for _, keyOp := range azkeys.PossibleKeyOperationValues() {
			if strVal == string(keyOp) {
				rv = append(rv, &selectedKeyOp)
			}
		}
	}

	return rv
}

func (cm *ConfidentialKeyModel) GetDestinationKeyCoordinate(defaultVaultName string) core.AzKeyVaultObjectCoordinate {
	vaultName := defaultVaultName
	if len(cm.DestinationKey.VaultName.ValueString()) > 0 {
		vaultName = cm.DestinationKey.VaultName.ValueString()
	}

	secretName := cm.DestinationKey.Name.ValueString()
	return core.AzKeyVaultObjectCoordinate{
		VaultName: vaultName,
		Name:      secretName,
	}
}

func (cm *ConfidentialKeyModel) Accept(key azkeys.KeyBundle, diagnostics *diag.Diagnostics) {
	cm.Id = types.StringValue(string(*key.Key.KID))

	if key.Tags != nil {
		tfTags := map[string]attr.Value{}

		for k, v := range key.Tags {
			if v != nil {
				tfTags[k] = types.StringValue(*v)
			}
		}
		cm.Tags, _ = types.MapValue(types.StringType, tfTags)
	}

	if key.Attributes != nil {
		cm.NotBefore = core.FormatTime(key.Attributes.NotBefore)
		cm.NotAfter = core.FormatTime(key.Attributes.Expires)
		cm.ConvertAzBool(key.Attributes.Enabled, &cm.Enabled)
	}

	cm.KeyVersion = types.StringValue(key.Key.KID.Version())
	cm.PublicKeyPem = types.StringNull()
	cm.PublicKeyOpenSSH = types.StringNull()

	cm.acceptPublicKey(key, diagnostics)
}

func (cm *ConfidentialKeyModel) acceptPublicKey(key azkeys.KeyBundle, diagnostics *diag.Diagnostics) {
	if key.Key.Kty == nil {
		return
	}

	kty := *key.Key.Kty

	if kty == azkeys.KeyTypeRSA || kty == azkeys.KeyTypeRSAHSM {
		publicKey := &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(key.Key.N),
			E: int(big.NewInt(0).SetBytes(key.Key.E).Uint64()),
		}
		cm.assignPublicKeysAttrs(publicKey, diagnostics)
	} else if kty == azkeys.KeyTypeEC || kty == azkeys.KeyTypeECHSM {
		publicKey := &ecdsa.PublicKey{
			X: big.NewInt(0).SetBytes(key.Key.X),
			Y: big.NewInt(0).SetBytes(key.Key.Y),
		}

		if key.Key.Crv != nil {
			if *key.Key.Crv == azkeys.CurveNameP256 {
				publicKey.Curve = elliptic.P256()
			} else if *key.Key.Crv == azkeys.CurveNameP384 {
				publicKey.Curve = elliptic.P384()
			} else if *key.Key.Crv == azkeys.CurveNameP521 {
				publicKey.Curve = elliptic.P521()
			} else {
				// This is not a supported curve.
				diagnostics.AddWarning(
					"Unsupported curve",
					fmt.Sprintf("Provider implementation cannot handle curve %s; public key cannot be automatically associated", *key.Key.Crv))
				return
			}
		}

		cm.assignPublicKeysAttrs(publicKey, diagnostics)
	}
}

func (cm *ConfidentialKeyModel) assignPublicKeysAttrs(pubKey interface{}, dg *diag.Diagnostics) {
	if pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey); err == nil {
		pubKeyPemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}

		cm.PublicKeyPem = types.StringValue(string(pem.EncodeToMemory(pubKeyPemBlock)))
	} else {
		dg.AddWarning("PKIX Warning", fmt.Sprintf("Attempt to marshal public key returned an error: %s", err.Error()))
	}

	// Not all key types can be SSH keys
	if sshPubKey, err := ssh.NewPublicKey(pubKey); err == nil {
		sshPubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
		cm.PublicKeyOpenSSH = types.StringValue(string(sshPubKeyBytes))
	} else {
		dg.AddWarning("SSH Warning", fmt.Sprintf("Attempt to marshal SSH public key returned an error: %s", err.Error()))
	}

}

type ConfidentialAzVaultKeyResource struct {
	ConfidentialResourceBase
}

func (d *ConfidentialAzVaultKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

//go:embed confidential_key.md
var confidentialKeyResourceMarkdownDescription string

func (d *ConfidentialAzVaultKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	specificAttrs := map[string]schema.Attribute{
		"key_opts": schema.SetAttribute{
			Description:         "Key operations this key is allowed",
			MarkdownDescription: "Key operations are allowed",

			Required: true,

			ElementType: types.StringType,

			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
				setvalidator.ValueStringsAre(
					stringvalidator.OneOf(
						string(azkeys.KeyOperationDecrypt),
						string(azkeys.KeyOperationEncrypt),
						string(azkeys.KeyOperationImport),
						string(azkeys.KeyOperationSign),
						string(azkeys.KeyOperationUnwrapKey),
						string(azkeys.KeyOperationVerify),
						string(azkeys.KeyOperationWrapKey),
					),
				),
			},
		},

		"hsm": schema.BoolAttribute{
			Description:         "Import this key into HSM",
			MarkdownDescription: "Import this key into HSM",
			Optional:            true,
		},

		"destination_key": schema.SingleNestedAttribute{
			Required:            true,
			MarkdownDescription: "Specification of a vault where this secret needs to be stored",
			Attributes: map[string]schema.Attribute{
				"vault_name": schema.StringAttribute{
					Optional:    true,
					Description: "Vault where the secret needs to be stored. If omitted, defaults to the vault containing the wrapping key",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"name": schema.StringAttribute{
					Optional:    false,
					Required:    true,
					Description: "Name of the secret to store",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
			},
		},

		"key_version": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Version of the secret created in the target vault",
			Description:         "Version of the secret created in the target vault",
		},
		"public_key_pem": schema.StringAttribute{
			Computed:            true,
			Description:         "PEM encoded RSA public key",
			MarkdownDescription: "PEM encoded RSA public key",
		},
		"public_key_openssh": schema.StringAttribute{
			Computed:            true,
			Description:         "The OpenSSH encoded public key of this Key Vault Key.",
			MarkdownDescription: "The OpenSSH encoded public key of this Key Vault Key.",
		},
	}

	resp.Schema = schema.Schema{
		Description:         "Creates a key in Azure KeyVault without revealing its value in state",
		MarkdownDescription: confidentialKeyResourceMarkdownDescription,

		Attributes: WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(specificAttrs),
	}
}

// Read perform READ operation. The reading operation checks whether the settings of the secret key are still aligned
// with the implementation.
func (d *ConfidentialAzVaultKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfidentialKeyModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The key version was never created; nothing needs to be read here.
	if data.KeyVersion.IsUnknown() {
		return
	}

	destSecretCoordinate, err := data.GetDestinationCoordinateFromId()
	tflog.Info(ctx, fmt.Sprintf("Received read ident: %s", data.Id.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("cannot establish reference to the created key version", err.Error())
		return
	}

	keyClient, err := d.factory.GetKeysClient(destSecretCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire keys client", fmt.Sprintf("Cannot acquire keys client to vault %s: %s", destSecretCoordinate.VaultName, err.Error()))
		return
	} else if keyClient == nil {
		resp.Diagnostics.AddError("Cannot acquire keys client", "Keys client returned is nil")
		return
	}

	keyState, err := keyClient.GetKey(ctx, destSecretCoordinate.Name, destSecretCoordinate.Version, nil)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read key", fmt.Sprintf("Cannot acquire key %s version %s from vault %s: %s",
			destSecretCoordinate.Name,
			destSecretCoordinate.Version,
			destSecretCoordinate.VaultName,
			err.Error()))
		return
	}
	if keyState.Key == nil {
		resp.Diagnostics.AddWarning(
			"Key removed outside of Terraform control",
			fmt.Sprintf("Aecret %s version %s from vault %s has been removed outside of Terraform control",
				destSecretCoordinate.Name,
				destSecretCoordinate.Version,
				destSecretCoordinate.Version),
		)
		return
	}

	data.Accept(keyState.KeyBundle, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *ConfidentialAzVaultKeyResource) convertToImportKeyParam(data *ConfidentialKeyModel) azkeys.ImportKeyParameters {
	keyAttributes := azkeys.KeyAttributes{
		Enabled:   data.Enabled.ValueBoolPointer(),
		Expires:   data.NotAfterDateAtPtr(),
		NotBefore: data.NotBeforeDateAtPtr(),
	}

	params := azkeys.ImportKeyParameters{
		KeyAttributes: &keyAttributes,
		Tags:          data.TagsAsPtr(),
		HSM:           data.HSM.ValueBoolPointer(),
		Key: &azkeys.JSONWebKey{
			KeyOps: data.GetKeyOperations(),
		},
	}

	return params
}

func (d *ConfidentialAzVaultKeyResource) convertToUpdateKeyParam(data *ConfidentialKeyModel) azkeys.UpdateKeyParameters {
	keyAttributes := azkeys.KeyAttributes{
		Enabled:   data.Enabled.ValueBoolPointer(),
		Expires:   data.NotAfterDateAtPtr(),
		NotBefore: data.NotBeforeDateAtPtr(),
	}

	params := azkeys.UpdateKeyParameters{
		KeyAttributes: &keyAttributes,
		Tags:          data.TagsAsPtr(),
		KeyOps:        data.GetKeyOperations(),
	}

	return params
}

func (d *ConfidentialAzVaultKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfidentialKeyModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	confidentialData := d.UnwrapEncryptedConfidentialData(ctx, data.ConfidentialMaterialModel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if confidentialData.Type != "key" && confidentialData.Type != "symmetric-key" {
		resp.Diagnostics.AddError("Unexpected object type", fmt.Sprintf("Expected key or symmtric, got %s", confidentialData.Type))
		return
	}

	destSecretCoordinate := d.factory.GetDestinationVaultObjectCoordinate(data.DestinationKey, "keys")

	d.factory.EnsureCanPlaceKeyVaultObjectAt(ctx, confidentialData, &destSecretCoordinate, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	keysClient, secErr := d.factory.GetKeysClient(destSecretCoordinate.VaultName)
	if secErr != nil {
		resp.Diagnostics.AddError("Error acquiring secret client", secErr.Error())
		return
	}

	params := d.convertToImportKeyParam(&data)

	if confidentialData.Type == "key" {
		if azJWKErr := core.PrivateKeyTOJSONWebKey(confidentialData.BinaryData, confidentialData.StringData, params.Key); azJWKErr != nil {
			resp.Diagnostics.AddError("Error converting private key to JSONWebKey", azJWKErr.Error())
			return
		}
	} else if confidentialData.Type == "symmetric-key" {
		if azJWKErr := core.SymmetricKeyTOJSONWebKey(confidentialData.BinaryData, params.Key); azJWKErr != nil {
			resp.Diagnostics.AddError("Error converting symmetric key to JSONWebKey", azJWKErr.Error())
			return
		}
	} else {
		resp.Diagnostics.AddError("Unsupported key material", fmt.Sprintf("Unsupported key type %s", confidentialData.Type))
	}

	setResp, setErr := keysClient.ImportKey(ctx, destSecretCoordinate.Name, params, nil)
	if setErr != nil {
		resp.Diagnostics.AddError("Error setting secret", setErr.Error())
		return
	}

	data.Accept(setResp.KeyBundle, &resp.Diagnostics)
	d.FlushState(ctx, confidentialData.Uuid, &data, resp)
}

func (d *ConfidentialAzVaultKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var stateData ConfidentialKeyModel
	var data ConfidentialKeyModel

	resp.Diagnostics.Append(req.State.Get(ctx, &stateData)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if d.DoUpdate(ctx, &stateData, &data, resp) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	}
}

func (d *ConfidentialAzVaultKeyResource) DoUpdate(ctx context.Context, stateData *ConfidentialKeyModel, data *ConfidentialKeyModel, resp *resource.UpdateResponse) StateFlushFlag {
	tflog.Info(ctx, fmt.Sprintf("Available object Id: %s", stateData.Id.ValueString()))

	destKeyCoordinate, err := stateData.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("Error getting destination secret coordinate", err.Error())
		return DoNotFlushState
	}

	destKeyCoordinateFromCfg := d.factory.GetDestinationVaultObjectCoordinate(data.DestinationKey, "keys")
	if !destKeyCoordinateFromCfg.SameAs(destKeyCoordinate.AzKeyVaultObjectCoordinate) {
		resp.Diagnostics.AddError(
			"Implicit object move",
			"The destination for this confidential key changed after the key was created. "+
				"This can happen e.g. when target vault was not explicitly specified. "+
				"Delete this key instead",
		)
		return DoNotFlushState
	}

	keyClient, err := d.factory.GetKeysClient(destKeyCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destKeyCoordinate.VaultName, err.Error()))
		return DoNotFlushState
	} else if keyClient == nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return DoNotFlushState
	}

	param := d.convertToUpdateKeyParam(data)
	tflog.Info(ctx, fmt.Sprintf("Updating with %d tags", len(param.Tags)))

	updateResponse, updateErr := keyClient.UpdateKey(ctx, destKeyCoordinate.Name, destKeyCoordinate.Version, param, nil)

	if updateErr != nil {
		resp.Diagnostics.AddError("Error updating secret properties", updateErr.Error())
		return DoNotFlushState
	}

	data.Accept(updateResponse.KeyBundle, &resp.Diagnostics)
	return FlushState
}

// Delete Performs DELETE operation on the created secret. The implementation disables the secret version
func (d *ConfidentialAzVaultKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfidentialKeyModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.KeyVersion.IsUnknown() {
		tflog.Warn(ctx, "Deleting resource that doesn't have recorded versioned coordinate.")
		return
	}

	destCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("Error getting destination secret coordinate", err.Error())
		return
	}

	keysClient, err := d.factory.GetKeysClient(destCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destCoordinate.VaultName, err.Error()))
		return
	} else if keysClient == nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return
	}

	enabledVal := false

	_, azErr := keysClient.UpdateKey(ctx,
		destCoordinate.Name,
		destCoordinate.Version,
		azkeys.UpdateKeyParameters{
			KeyAttributes: &azkeys.KeyAttributes{
				Enabled: &enabledVal,
			},
		},
		nil,
	)

	if azErr != nil {
		resp.Diagnostics.AddError("Cannot disable key  version", fmt.Sprintf("Request to disable key's %s version %s in vault %s failed: %s",
			destCoordinate.Name,
			destCoordinate.Version,
			destCoordinate.VaultName,
			azErr.Error(),
		))
	}
}

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &ConfidentialAzVaultKeyResource{}

func NewConfidentialAzVaultKeyResource() resource.Resource {
	return &ConfidentialAzVaultKeyResource{}
}
