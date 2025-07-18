package keyvault

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
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/crypto/ssh"
	"math/big"
)

type ConfidentialKeyModel struct {
	resources.WrappedAzKeyVaultObjectConfidentialMaterialModel

	HSM            types.Bool                           `tfsdk:"hsm"`
	DestinationKey core.AzKeyVaultObjectCoordinateModel `tfsdk:"destination_key"`
	KeyOperations  types.Set                            `tfsdk:"key_opts"`

	KeyVersion types.String `tfsdk:"key_version"`

	PublicKeyPem     types.String `tfsdk:"public_key_pem"`
	PublicKeyOpenSSH types.String `tfsdk:"public_key_openssh"`
}

func (cm *ConfidentialKeyModel) GetKeyOperations(ctx context.Context) []*azkeys.KeyOperation {
	var rv []*azkeys.KeyOperation

	if !cm.KeyOperations.IsNull() && !cm.KeyOperations.IsUnknown() {
		strElements := make([]string, len(cm.KeyOperations.Elements()))
		cm.KeyOperations.ElementsAs(ctx, &strElements, false)

	outer:
		for _, val := range strElements {
			for _, keyOp := range azkeys.PossibleKeyOperationValues() {
				if val == string(keyOp) {
					rv = append(rv, &keyOp)
					continue outer
				}
			}
		}
	}

	return rv
}

func (cm *ConfidentialKeyModel) ConvertToImportKeyParam(ctx context.Context) azkeys.ImportKeyParameters {
	keyAttributes := azkeys.KeyAttributes{
		Enabled:   cm.Enabled.ValueBoolPointer(),
		Expires:   cm.NotAfterDateAtPtr(),
		NotBefore: cm.NotBeforeDateAtPtr(),
	}

	params := azkeys.ImportKeyParameters{
		KeyAttributes: &keyAttributes,
		Tags:          cm.TagsAsPtr(),
		HSM:           cm.HSM.ValueBoolPointer(),
		Key: &azkeys.JSONWebKey{
			KeyOps: cm.GetKeyOperations(ctx),
		},
	}

	return params
}

func (cm *ConfidentialKeyModel) ConvertToUpdateKeyParam(ctx context.Context) azkeys.UpdateKeyParameters {
	keyAttributes := azkeys.KeyAttributes{
		Enabled:   cm.Enabled.ValueBoolPointer(),
		Expires:   cm.NotAfterDateAtPtr(),
		NotBefore: cm.NotBeforeDateAtPtr(),
	}

	params := azkeys.UpdateKeyParameters{
		KeyAttributes: &keyAttributes,
		Tags:          cm.TagsAsPtr(),
		KeyOps:        cm.GetKeyOperations(ctx),
	}

	return params
}

func (cm *ConfidentialKeyModel) GetDestinationKeyCoordinate(defaultVaultName string) core.AzKeyVaultObjectCoordinate {
	vaultName := defaultVaultName
	if len(cm.DestinationKey.VaultName.ValueString()) > 0 {
		vaultName = cm.DestinationKey.VaultName.ValueString()
	}

	keyName := cm.DestinationKey.Name.ValueString()
	return core.AzKeyVaultObjectCoordinate{
		VaultName: vaultName,
		Name:      keyName,
		Type:      "keys",
	}
}

func (cm *ConfidentialKeyModel) Accept(key azkeys.KeyBundle, diagnostics *diag.Diagnostics) {
	if key.Key == nil {
		diagnostics.AddWarning("Superfluous key conversion", "Received null key to convert into existing state")
		return
	}

	if key.Key.KID != nil {
		if cm.Id.IsUnknown() {
			cm.Id = types.StringValue(string(*key.Key.KID))
		} else if cm.Id.ValueString() != string(*key.Key.KID) {
			diagnostics.AddError("Conflicting key", "Key identifier cannot be changed after the key was created; yet a different value was received")
		}

		if cm.KeyVersion.IsUnknown() {
			cm.KeyVersion = types.StringValue(key.Key.KID.Version())
		} else if cm.KeyVersion.ValueString() != key.Key.KID.Version() {
			diagnostics.AddError("Conflicting key version", "Key identifier cannot be changed after the key was created; yet a different version was received")
		}
	} else {
		diagnostics.AddError("Conversion request for key having nil key identifier", "Every key must have a valid Key ID when converting")
	}

	cm.ConvertAzMap(key.Tags, &cm.Tags)

	if key.Attributes != nil {
		cm.NotBefore = core.FormatTime(key.Attributes.NotBefore)
		cm.NotAfter = core.FormatTime(key.Attributes.Expires)
		cm.ConvertAzBool(key.Attributes.Enabled, &cm.Enabled)
	}

	// Convert key options if these are specified
	if key.Key.KeyOps != nil && len(key.Key.KeyOps) > 0 {
		keyOps, keyOpsErr := core.ConvertToTerraformSet(
			func(k *azkeys.KeyOperation) attr.Value { return types.StringValue(string(*k)) },
			types.StringType,
			key.Key.KeyOps...)

		if keyOpsErr != nil {
			diagnostics.AddError("Error converting key operations", keyOpsErr.Error())
		} else {
			cm.KeyOperations = keyOps
		}
	} else {
		// The data in the model will change only if the model
		if cm.SetContainsValues(&cm.KeyOperations) || cm.KeyOperations.IsUnknown() {
			cm.KeyOperations = types.SetNull(types.StringType)
		}
	}

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

//go:embed confidential_key.md
var confidentialKeyResourceMarkdownDescription string

type AzKeyVaultKeyResourceSpecializer struct {
	factory core.AZClientsFactory
}

func (a *AzKeyVaultKeyResourceSpecializer) SetFactory(factory core.AZClientsFactory) {
	a.factory = factory
}

func (a *AzKeyVaultKeyResourceSpecializer) NewTerraformModel() ConfidentialKeyModel {
	return ConfidentialKeyModel{}
}

func (a *AzKeyVaultKeyResourceSpecializer) AssignIdTo(azObj azkeys.KeyBundle, tfModel *ConfidentialKeyModel) {
	kid := azObj.Key.KID
	if kid != nil {
		tfModel.Id = types.StringValue(string(*kid))
	}
}

func (a *AzKeyVaultKeyResourceSpecializer) ConvertToTerraform(azObj azkeys.KeyBundle, tfModel *ConfidentialKeyModel) diag.Diagnostics {
	dg := diag.Diagnostics{}
	tfModel.Accept(azObj, &dg)
	return dg
}

func (a *AzKeyVaultKeyResourceSpecializer) GetConfidentialMaterialFrom(mdl ConfidentialKeyModel) resources.ConfidentialMaterialModel {
	return mdl.ConfidentialMaterialModel
}

func (a *AzKeyVaultKeyResourceSpecializer) GetSupportedConfidentialMaterialTypes() []string {
	return []string{"key", "symmetric-key"}
}

func (a *AzKeyVaultKeyResourceSpecializer) CheckPlacement(ctx context.Context, tfModel *ConfidentialKeyModel, cf core.VersionedBinaryConfidentialData) diag.Diagnostics {
	rv := diag.Diagnostics{}

	destKeyCoordinate := a.factory.GetDestinationVaultObjectCoordinate(tfModel.DestinationKey, "keys")

	a.factory.EnsureCanPlaceKeyVaultObjectAt(ctx, cf, &destKeyCoordinate, &rv)
	return rv
}

func (a *AzKeyVaultKeyResourceSpecializer) DoRead(ctx context.Context, data *ConfidentialKeyModel) (azkeys.KeyBundle, resources.ResourceExistenceCheck, diag.Diagnostics) {
	rv := diag.Diagnostics{}

	// The key version was never created; nothing needs to be read here.
	if data.Id.IsUnknown() {
		return azkeys.KeyBundle{}, resources.ResourceNotYetCreated, rv

	}

	destSecretCoordinate, err := data.GetDestinationCoordinateFromId()
	tflog.Info(ctx, fmt.Sprintf("Received read ident: %s", data.Id.ValueString()))

	if err != nil {
		rv.AddError("cannot establish reference to the created key version", err.Error())
		return azkeys.KeyBundle{}, resources.ResourceCheckError, rv
	}

	keyClient, err := a.factory.GetKeysClient(destSecretCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire keys client", fmt.Sprintf("Cannot acquire keys client to vault %s: %s", destSecretCoordinate.VaultName, err.Error()))
		return azkeys.KeyBundle{}, resources.ResourceCheckError, rv
	} else if keyClient == nil {
		rv.AddError("Cannot acquire keys client", "Keys client returned is nil")
		return azkeys.KeyBundle{}, resources.ResourceCheckError, rv
	}

	keyState, err := keyClient.GetKey(ctx, destSecretCoordinate.Name, destSecretCoordinate.Version, nil)
	if err != nil {
		if core.IsResourceNotFoundError(err) {
			if a.factory.IsObjectTrackingEnabled() {
				rv.AddWarning(
					"Key removed from key vault",
					fmt.Sprintf("Key %s version %s is no longer in vault %s. The provider tracks confidential objects; creating this key again will be rejected as duplicate. If creathing this key again is intentional, re-encrypt ciphertext.",
						destSecretCoordinate.Name,
						destSecretCoordinate.Version,
						destSecretCoordinate.VaultName,
					),
				)
			}

			return azkeys.KeyBundle{}, resources.ResourceNotFound, rv
		} else {
			rv.AddError("Cannot read key", fmt.Sprintf("Cannot acquire key %s version %s from vault %s: %s",
				destSecretCoordinate.Name,
				destSecretCoordinate.Version,
				destSecretCoordinate.VaultName,
				err.Error()))
			return keyState.KeyBundle, resources.ResourceCheckError, rv
		}
	}

	return keyState.KeyBundle, resources.ResourceExists, rv
}

func (a *AzKeyVaultKeyResourceSpecializer) DoCreate(ctx context.Context, data *ConfidentialKeyModel, confidentialData core.VersionedBinaryConfidentialData) (azkeys.KeyBundle, diag.Diagnostics) {
	rvDiag := diag.Diagnostics{}

	//gunzip, gunzipErr := core.GZipDecompress(confidentialData.GetBinaryData())
	//if gunzipErr != nil {
	//	rvDiag.AddError("Binary data is not GZip-compressed", gunzipErr.Error())
	//	return azkeys.KeyBundle{}, rvDiag
	//}

	params := data.ConvertToImportKeyParam(ctx)

	jwkSet, jwkErr := jwk.Parse(confidentialData.GetBinaryData())
	if jwkErr != nil {
		rvDiag.AddError("Cannot read JSON Web Key data", jwkErr.Error())
		return azkeys.KeyBundle{}, rvDiag
	}
	if convertErr := core.ConvertJWKSToAzJWK(jwkSet, params.Key); convertErr != nil {
		rvDiag.AddError("Cannot convert supplied JSON Web Key to required Azure data structure; please use supplied conversion tool or provider method", convertErr.Error())
		return azkeys.KeyBundle{}, rvDiag
	}

	destSecretCoordinate := a.factory.GetDestinationVaultObjectCoordinate(data.DestinationKey, "keys")
	keysClient, secErr := a.factory.GetKeysClient(destSecretCoordinate.VaultName)
	if secErr != nil {
		rvDiag.AddError("Az key vault keys client cannot be retrieved", secErr.Error())
		return azkeys.KeyBundle{}, rvDiag
	} else if keysClient == nil {
		rvDiag.AddError("Az key vault keys client cannot be retrieved", "Nil client returned while no error was raised. This is a provider bug. Please report this")
		return azkeys.KeyBundle{}, rvDiag
	}

	setResp, setErr := keysClient.ImportKey(ctx, destSecretCoordinate.Name, params, nil)
	if setErr != nil {
		rvDiag.AddError("Error import key", setErr.Error())
		return azkeys.KeyBundle{}, rvDiag
	}

	return setResp.KeyBundle, rvDiag
}

func (a *AzKeyVaultKeyResourceSpecializer) DoUpdate(ctx context.Context, data *ConfidentialKeyModel) (azkeys.KeyBundle, diag.Diagnostics) {
	tflog.Info(ctx, fmt.Sprintf("Available object Id: %s", data.Id.ValueString()))

	rv := diag.Diagnostics{}
	destKeyCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("Error getting destination key coordinate", err.Error())
		return azkeys.KeyBundle{}, rv
	}

	destKeyCoordinateFromCfg := a.factory.GetDestinationVaultObjectCoordinate(data.DestinationKey, "keys")
	if !destKeyCoordinateFromCfg.SameAs(destKeyCoordinate.AzKeyVaultObjectCoordinate) {
		rv.AddError(
			"Implicit object move",
			"The destination for this confidential key changed after the key was created. "+
				"This can happen e.g. when target vault was not explicitly specified. "+
				"Delete this key instead",
		)
		return azkeys.KeyBundle{}, rv
	}

	keyClient, err := a.factory.GetKeysClient(destKeyCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire keys client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destKeyCoordinate.VaultName, err.Error()))
		return azkeys.KeyBundle{}, rv
	} else if keyClient == nil {
		rv.AddError("Cannot acquire keys client", "Keys client returned is nil")
		return azkeys.KeyBundle{}, rv
	}

	param := data.ConvertToUpdateKeyParam(ctx)
	tflog.Info(ctx, fmt.Sprintf("Updating with %d tags", len(param.Tags)))

	updateResponse, updateErr := keyClient.UpdateKey(ctx, destKeyCoordinate.Name, destKeyCoordinate.Version, param, nil)

	if updateErr != nil {
		rv.AddError("Error updating key properties", updateErr.Error())
		return azkeys.KeyBundle{}, rv
	}

	return updateResponse.KeyBundle, rv
}

func (a *AzKeyVaultKeyResourceSpecializer) DoDelete(ctx context.Context, data *ConfidentialKeyModel) diag.Diagnostics {
	rv := diag.Diagnostics{}

	if data.Id.IsUnknown() {
		tflog.Warn(ctx, "Deleting resource that doesn't have recorded versioned coordinate.")
		rv.AddWarning("Superfluous delete call", "Delete key was called where key Id is not yet known")
		return rv
	}

	destCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("Error getting destination key coordinate", err.Error())
		return rv
	}

	keysClient, err := a.factory.GetKeysClient(destCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire keys client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destCoordinate.VaultName, err.Error()))
		return rv
	} else if keysClient == nil {
		rv.AddError("Cannot acquire keys client", "Keys client returned is nil. This is a provider error. Please report this issue")
		return rv
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
		rv.AddError("Cannot disable key version", fmt.Sprintf("Request to disable key's %s version %s in vault %s failed: %s",
			destCoordinate.Name,
			destCoordinate.Version,
			destCoordinate.VaultName,
			azErr.Error(),
		))
	}

	return rv
}

func (a *AzKeyVaultKeyResourceSpecializer) GetPlaintextImporter() core.ObjectExportSupport[core.VersionedBinaryConfidentialData, []byte] {
	return core.NewVersionedBinaryConfidentialDataHelper()
}

func NewConfidentialAzVaultKeyResource() resource.Resource {
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
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.RequiresReplace(),
			},
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

	resourceSchema := schema.Schema{
		Description:         "Creates a key in Azure KeyVault without revealing its value in state",
		MarkdownDescription: confidentialKeyResourceMarkdownDescription,

		Attributes: resources.WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(specificAttrs),
	}

	return &resources.ConfidentialGenericResource[ConfidentialKeyModel, int, core.VersionedBinaryConfidentialData, azkeys.KeyBundle]{
		Specializer:    &AzKeyVaultKeyResourceSpecializer{},
		ResourceType:   "key",
		ResourceSchema: resourceSchema,
	}
}
