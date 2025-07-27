package keyvault

import (
	"context"
	"crypto/rsa"
	_ "embed"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type SecretModel struct {
	resources.WrappedAzKeyVaultObjectConfidentialMaterialModel

	ContentType       types.String                         `tfsdk:"content_type"`
	DestinationSecret core.AzKeyVaultObjectCoordinateModel `tfsdk:"destination_secret"`

	SecretVersion types.String `tfsdk:"secret_version"`
}

func (cm *SecretModel) ConvertToSetSecretParam(data *SecretModel) azsecrets.SetSecretParameters {
	secretAttributes := azsecrets.SecretAttributes{
		Enabled:   data.Enabled.ValueBoolPointer(),
		Expires:   data.NotAfterDateAtPtr(),
		NotBefore: data.NotBeforeDateAtPtr(),
	}

	params := azsecrets.SetSecretParameters{
		ContentType:      data.ContentTypeAsPtr(),
		Tags:             data.TagsAsPtr(),
		SecretAttributes: &secretAttributes,
	}

	return params
}

func (cm *SecretModel) ConvertToUpdateSecretPropertiesParam(data *SecretModel) azsecrets.UpdateSecretPropertiesParameters {
	secretAttributes := azsecrets.SecretAttributes{
		Enabled:   data.Enabled.ValueBoolPointer(),
		Expires:   data.NotAfterDateAtPtr(),
		NotBefore: data.NotBeforeDateAtPtr(),
	}

	params := azsecrets.UpdateSecretPropertiesParameters{
		ContentType:      data.ContentTypeAsPtr(),
		Tags:             data.TagsAsPtr(),
		SecretAttributes: &secretAttributes,
	}

	return params
}

func (cm *SecretModel) ContentTypeAsPtr() *string {
	return cm.StringTypeAsPtr(&cm.ContentType)
}

func (cm *SecretModel) GetDestinationSecretCoordinate(defaultVaultName string) core.AzKeyVaultObjectCoordinate {
	vaultName := defaultVaultName
	if len(cm.DestinationSecret.VaultName.ValueString()) > 0 {
		vaultName = cm.DestinationSecret.VaultName.ValueString()
	}

	secretName := cm.DestinationSecret.Name.ValueString()
	return core.AzKeyVaultObjectCoordinate{
		VaultName: vaultName,
		Name:      secretName,
		Type:      "secret",
	}
}

func (cm *SecretModel) Accept(secret azsecrets.Secret) {
	cm.Id = types.StringValue(string(*secret.ID))

	cm.ConvertAzString(secret.ContentType, &cm.ContentType)
	cm.ConvertAzMap(secret.Tags, &cm.Tags)

	if secret.Attributes != nil {
		cm.NotBefore = core.FormatTime(secret.Attributes.NotBefore)
		cm.NotAfter = core.FormatTime(secret.Attributes.Expires)
		cm.ConvertAzBool(secret.Attributes.Enabled, &cm.Enabled)
	}

	cm.SecretVersion = types.StringValue(secret.ID.Version())
}

// AzKeyVaultSecretResourceSpecializer Generified Implementation
type AzKeyVaultSecretResourceSpecializer struct {
	factory core.AZClientsFactory
}

func (a *AzKeyVaultSecretResourceSpecializer) SetFactory(factory core.AZClientsFactory) {
	a.factory = factory
}

func (a *AzKeyVaultSecretResourceSpecializer) NewTerraformModel() SecretModel {
	return SecretModel{}
}

func (a *AzKeyVaultSecretResourceSpecializer) AssignIdTo(secret azsecrets.Secret, tfModel *SecretModel) {
	idVal := secret.ID
	if idVal != nil {
		tfModel.Id = types.StringValue(string(*idVal))
	}
}

func (a *AzKeyVaultSecretResourceSpecializer) ConvertToTerraform(secret azsecrets.Secret, tfModel *SecretModel) diag.Diagnostics {
	tfModel.Accept(secret)
	return nil
}

func (a *AzKeyVaultSecretResourceSpecializer) GetConfidentialMaterialFrom(mdl SecretModel) resources.ConfidentialMaterialModel {
	return mdl.ConfidentialMaterialModel
}

func (a *AzKeyVaultSecretResourceSpecializer) GetSupportedConfidentialMaterialTypes() []string {
	return []string{SecretObjectType}
}

func (a *AzKeyVaultSecretResourceSpecializer) CheckPlacement(ctx context.Context, pc []core.ProviderConstraint, pl []core.PlacementConstraint, tfModel *SecretModel) diag.Diagnostics {
	rv := diag.Diagnostics{}

	destSecretCoordinate := a.factory.GetDestinationVaultObjectCoordinate(tfModel.DestinationSecret, "secrets")

	a.factory.EnsureCanPlaceLabelledObjectAt(ctx, pc, pl, "secret", &destSecretCoordinate, &rv)
	return rv
}

func (a *AzKeyVaultSecretResourceSpecializer) DoRead(ctx context.Context, data *SecretModel) (azsecrets.Secret, resources.ResourceExistenceCheck, diag.Diagnostics) {
	rv := diag.Diagnostics{}
	// The secret version was never created; nothing needs to be read here.
	if data.Id.IsUnknown() {
		tflog.Info(ctx, "Secret version is not yet known during read; the secret was never created.")
		return azsecrets.Secret{}, resources.ResourceNotYetCreated, rv
	}

	destSecretCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("cannot establish reference to the created secret version", err.Error())
		return azsecrets.Secret{}, resources.ResourceCheckError, rv
	}

	secretClient, err := a.factory.GetSecretsClient(destSecretCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destSecretCoordinate.VaultName, err.Error()))
		return azsecrets.Secret{}, resources.ResourceCheckError, rv
	} else if secretClient == nil {
		rv.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return azsecrets.Secret{}, resources.ResourceCheckError, rv
	}

	secretState, err := secretClient.GetSecret(ctx, destSecretCoordinate.Name, destSecretCoordinate.Version, nil)
	if err != nil {
		if core.IsResourceNotFoundError(err) {
			if a.factory.IsObjectTrackingEnabled() {
				rv.AddWarning(
					"Secret removed from key vault",
					fmt.Sprintf("Secret %s version %s is no longer in vault %s. The provider tracks confidential objects; creating this secret again will be rejected as duplicate. If creathing this secret again is intentional, re-encrypt ciphertext.",
						destSecretCoordinate.Name,
						destSecretCoordinate.Version,
						destSecretCoordinate.VaultName,
					),
				)
			}

			return azsecrets.Secret{}, resources.ResourceNotFound, rv
		} else {
			rv.AddError("Cannot read secret", fmt.Sprintf("Cannot acquire secret %s version %s from vault %s: %s",
				destSecretCoordinate.Name,
				destSecretCoordinate.Version,
				destSecretCoordinate.VaultName,
				err.Error()))
		}
		return azsecrets.Secret{}, resources.ResourceCheckError, rv
	}

	return secretState.Secret, resources.ResourceExists, rv
}

func (a *AzKeyVaultSecretResourceSpecializer) DoCreate(ctx context.Context, data *SecretModel, unwrappedData core.ConfidentialStringData) (azsecrets.Secret, diag.Diagnostics) {
	rv := diag.Diagnostics{}
	destSecretCoordinate := a.factory.GetDestinationVaultObjectCoordinate(data.DestinationSecret, "secrets")

	secretClient, secErr := a.factory.GetSecretsClient(destSecretCoordinate.VaultName)
	if secErr != nil {
		rv.AddError("Error acquiring secret client", secErr.Error())
		return azsecrets.Secret{}, rv
	} else if secretClient == nil {
		rv.AddError("Error acquiring secret client", "Returned nil client without raising an error")
		return azsecrets.Secret{}, rv
	}

	params := data.ConvertToSetSecretParam(data)
	secretValue := unwrappedData.GetStingData()
	params.Value = to.Ptr(secretValue)

	setResp, setErr := secretClient.SetSecret(ctx, destSecretCoordinate.Name, params, nil)
	if setErr != nil {
		rv.AddError("Error setting secret", setErr.Error())
		return azsecrets.Secret{}, rv
	} else {
		return setResp.Secret, rv
	}
}

func (a *AzKeyVaultSecretResourceSpecializer) DoUpdate(ctx context.Context, data *SecretModel) (azsecrets.Secret, diag.Diagnostics) {
	rv := diag.Diagnostics{}
	destSecretCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("Resource identifier does not conform to the expected format", err.Error())
		return azsecrets.Secret{}, rv
	}

	destSecretCoordinateFromCfg := a.factory.GetDestinationVaultObjectCoordinate(data.DestinationSecret, "secrets")
	if !destSecretCoordinateFromCfg.SameAs(destSecretCoordinate.AzKeyVaultObjectCoordinate) {
		//resp.Diagnostics.AddError("Value mismatch", fmt.Sprintf("%s != %s", destSecretCoordinate.AzKeyVaultObjectCoordinate.AsString(), destSecretCoordinateFromCfg.AsString()))
		rv.AddError(
			"Implicit object move",
			"The destination for this confidential secret changed after the secret was created. "+
				"This can happen e.g. when target vault was not explicitly specified. "+
				"Delete this secret instead",
		)
		return azsecrets.Secret{}, rv
	}

	secretClient, err := a.factory.GetSecretsClient(destSecretCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destSecretCoordinate.VaultName, err.Error()))
		return azsecrets.Secret{}, rv
	} else if secretClient == nil {
		rv.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return azsecrets.Secret{}, rv
	}

	param := data.ConvertToUpdateSecretPropertiesParam(data)
	secretResp, updateErr := secretClient.UpdateSecretProperties(ctx, destSecretCoordinate.Name, destSecretCoordinate.Version, param, nil)

	if updateErr != nil {
		rv.AddError("Error updating secret properties", updateErr.Error())
		return azsecrets.Secret{}, rv
	}

	return secretResp.Secret, rv
}

func (a *AzKeyVaultSecretResourceSpecializer) DoDelete(ctx context.Context, data *SecretModel) diag.Diagnostics {
	rv := diag.Diagnostics{}
	if data.Id.IsUnknown() {
		tflog.Warn(ctx, "Deleting resource that doesn't have recorded versioned coordinate.")
		rv.AddWarning("Incomplete configuration", "secret version is not specified when the resource is being deleted; did it ever exist?")
		return rv
	}

	destCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("Error getting secret coordinate", err.Error())
		return rv
	}

	secretClient, err := a.factory.GetSecretsClient(destCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destCoordinate.VaultName, err.Error()))
		return rv
	} else if secretClient == nil {
		rv.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return rv
	}

	enabledVal := false

	_, azErr := secretClient.UpdateSecretProperties(ctx,
		destCoordinate.Name,
		destCoordinate.Version,
		azsecrets.UpdateSecretPropertiesParameters{
			SecretAttributes: &azsecrets.SecretAttributes{
				Enabled: &enabledVal,
			},
		},
		nil,
	)

	if azErr != nil {
		rv.AddError("Cannot disable secret version", fmt.Sprintf("Request to disable secret's %s version %s in vault %s failed: %s",
			destCoordinate.Name,
			destCoordinate.Version,
			destCoordinate.VaultName,
			azErr.Error(),
		))
	}

	return rv
}

func (a *AzKeyVaultSecretResourceSpecializer) GetJsonDataImporter() core.ObjectJsonImportSupport[core.ConfidentialStringData] {
	return core.NewVersionedStringConfidentialDataHelper(SecretObjectType)
}

// --------------------------------------------------------------------------------
// Factory method

//go:embed secret.md
var secretResourceMarkdownDescription string

const SecretObjectType = "kv/secret"

func NewSecretResource() resource.Resource {
	modelAttributes := map[string]schema.Attribute{
		"content_type": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Content type of the secret, if required",
		},

		"destination_secret": schema.SingleNestedAttribute{
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

		"secret_version": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Version of the secret created in the target vault",
			Description:         "Version of the secret created in the target vault",
		},
	}

	resourceSchema := schema.Schema{
		Description:         "Creates a secret in Azure KeyVault without revealing its value in state",
		MarkdownDescription: secretResourceMarkdownDescription,

		Attributes: resources.WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(modelAttributes),
	}

	kvSecretSpecializer := &AzKeyVaultSecretResourceSpecializer{}

	return &resources.ConfidentialGenericResource[SecretModel, int, core.ConfidentialStringData, azsecrets.Secret]{
		Specializer:    kvSecretSpecializer,
		ImmutableRU:    kvSecretSpecializer,
		ResourceName:   "secret",
		ResourceSchema: resourceSchema,
	}
}

type AzKVObjectCoordinateParamValidator struct{}

func (v *AzKVObjectCoordinateParamValidator) ValidateParameterObject(ctx context.Context, req function.ObjectParameterValidatorRequest, res *function.ObjectParameterValidatorResponse) {

	// The validator ignores the null values, which mean "any destination".
	if req.Value.IsUnknown() || req.Value.IsNull() {
		return
	}

	p := core.AzKeyVaultObjectCoordinateModel{}
	req.Value.As(ctx, &p, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})

	if len(p.VaultName.ValueString()) == 0 || len(p.Name.ValueString()) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Both vault name and object name must be specified to lock the destination"))
	}
}

func CreateSecretEncryptedMessage(confidentialString string, coord *core.AzKeyVaultObjectCoordinate, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, core.SecondaryProtectionParameters, error) {
	helper := core.NewVersionedStringConfidentialDataHelper(SecretObjectType)

	if coord != nil {
		md.PlacementConstraints = []core.PlacementConstraint{core.PlacementConstraint(coord.GetLabel())}
	}

	helper.CreateConfidentialStringData(confidentialString, md)
	em, err := helper.ToEncryptedMessage(pubKey)
	return em, md, err
}

func NewSecretEncryptorFunction() function.Function {
	rv := resources.FunctionTemplate[string, core.AzKeyVaultObjectCoordinateModel]{
		Name:                "encrypt_keyvault_secret",
		Summary:             "Produces a ciphertext string suitable for use with az-confidential_secret resource",
		MarkdownDescription: "Encrypts a secret string without the use of the `tfgen` tool",

		DataParameter: function.StringParameter{
			Name:        "secret",
			Description: "Secret value that should appear in the key vault",
		},
		DestinationParameter: function.ObjectParameter{
			Name:               "destination_secret",
			Description:        "Destination vault and secret name",
			AllowNullValue:     true,
			AllowUnknownValues: true,

			AttributeTypes: map[string]attr.Type{
				"vault_name": types.StringType,
				"name":       types.StringType,
			},

			Validators: []function.ObjectParameterValidator{
				&AzKVObjectCoordinateParamValidator{},
			},
		},
		ConfidentialModelSupplier: func() string { return "" },
		DestinationModelSupplier: func() *core.AzKeyVaultObjectCoordinateModel {
			var ptr *core.AzKeyVaultObjectCoordinateModel
			return ptr
		},

		CreatEncryptedMessage: func(confidentialModel string, dest *core.AzKeyVaultObjectCoordinateModel, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, error) {
			var coord *core.AzKeyVaultObjectCoordinate
			if dest != nil {
				coord = &core.AzKeyVaultObjectCoordinate{
					VaultName: dest.VaultName.ValueString(),
					Name:      dest.Name.ValueString(),
					Type:      "secrets",
				}
			}

			em, _, err := CreateSecretEncryptedMessage(confidentialModel, coord, md, pubKey)
			return em, err
		},
	}

	return &rv
}
