package resources

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type ConfidentialSecretModel struct {
	WrappedAzKeyVaultObjectConfidentialMaterialModel

	ContentType       types.String                         `tfsdk:"content_type"`
	DestinationSecret core.AzKeyVaultObjectCoordinateModel `tfsdk:"destination_secret"`

	SecretVersion types.String `tfsdk:"secret_version"`
}

func (cm *ConfidentialSecretModel) ContentTypeAsPtr() *string {
	return cm.StringTypeAsPtr(&cm.ContentType)
}

func (cm *ConfidentialSecretModel) GetDestinationSecretCoordinate(defaultVaultName string) core.AzKeyVaultObjectCoordinate {
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

func (cm *ConfidentialSecretModel) Accept(secret azsecrets.Secret) {
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

type ConfidentialAzVaultSecretResource struct {
	ConfidentialResourceBase
}

func (d *ConfidentialAzVaultSecretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

//go:embed confidential_secret.md
var secretResourceMarkdownDescription string

func (d *ConfidentialAzVaultSecretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	specificAttrs := map[string]schema.Attribute{
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

	resp.Schema = schema.Schema{
		Description:         "Creates a secret in Azure KeyVault without revealing its value in state",
		MarkdownDescription: secretResourceMarkdownDescription,

		Attributes: WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(specificAttrs),
	}

}

// Read perform READ operation. The reading operation checks whether the settings of the secret key are still aligned
// with the implementation.
func (d *ConfidentialAzVaultSecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfidentialSecretModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretState, doStateFlush := d.DoRead(ctx, &data, resp)

	if doStateFlush {
		data.Accept(secretState.Secret)
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	}
}

func (d *ConfidentialAzVaultSecretResource) DoRead(ctx context.Context, data *ConfidentialSecretModel, resp *resource.ReadResponse) (azsecrets.GetSecretResponse, StateFlushFlag) {
	// The secret version was never created; nothing needs to be read here.
	if data.SecretVersion.IsUnknown() {
		tflog.Info(ctx, "Secret version is not yet known during read; the secret was never created.")
		return azsecrets.GetSecretResponse{}, DoNotFlushState
	}

	destSecretCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("cannot establish reference to the created secret version", err.Error())
		return azsecrets.GetSecretResponse{}, DoNotFlushState
	}

	secretClient, err := d.factory.GetSecretsClient(destSecretCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destSecretCoordinate.VaultName, err.Error()))
		return azsecrets.GetSecretResponse{}, DoNotFlushState
	} else if secretClient == nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return azsecrets.GetSecretResponse{}, DoNotFlushState
	}

	secretState, err := secretClient.GetSecret(ctx, destSecretCoordinate.Name, destSecretCoordinate.Version, nil)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read secret", fmt.Sprintf("Cannot acquire secret %s version %s from vault %s: %s",
			destSecretCoordinate.Name,
			destSecretCoordinate.Version,
			destSecretCoordinate.VaultName,
			err.Error()))
		return azsecrets.GetSecretResponse{}, DoNotFlushState
	}
	if secretState.ID == nil {
		resp.Diagnostics.AddWarning(
			"Secret removed outside of Terraform control",
			fmt.Sprintf("Aecret %s version %s from vault %s has been removed outside of Terraform control",
				destSecretCoordinate.Name,
				destSecretCoordinate.Version,
				destSecretCoordinate.Version),
		)
		return azsecrets.GetSecretResponse{}, DoNotFlushState
	}

	return secretState, FlushState
}

func (d *ConfidentialAzVaultSecretResource) convertToSetSecretParam(data *ConfidentialSecretModel) azsecrets.SetSecretParameters {
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

func (d *ConfidentialAzVaultSecretResource) convertToUpdateSecretPropertiesParam(data *ConfidentialSecretModel) azsecrets.UpdateSecretPropertiesParameters {
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

func (d *ConfidentialAzVaultSecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfidentialSecretModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	unwrappedPayload := d.UnwrapEncryptedConfidentialData(ctx, data.ConfidentialMaterialModel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if unwrappedPayload.Type != "secret" {
		resp.Diagnostics.AddError("Unexpected object type", fmt.Sprintf("Expected secret, got %s", unwrappedPayload.Type))
		return
	}

	destSecretCoordinate := d.factory.GetDestinationVaultObjectCoordinate(data.DestinationSecret, "secrets")

	d.factory.EnsureCanPlace(ctx, unwrappedPayload, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	secretClient, secErr := d.factory.GetSecretsClient(destSecretCoordinate.VaultName)
	if secErr != nil {
		resp.Diagnostics.AddError("Error acquiring secret client", secErr.Error())
		return
	}

	params := d.convertToSetSecretParam(&data)
	params.Value = &unwrappedPayload.StringData

	setResp, setErr := secretClient.SetSecret(ctx, destSecretCoordinate.Name, params, nil)
	if setErr != nil {
		resp.Diagnostics.AddError("Error setting secret", setErr.Error())
		return
	}

	data.Accept(setResp.Secret)
	d.FlushState(ctx, unwrappedPayload.Uuid, &data, resp)
}

func (d *ConfidentialAzVaultSecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var stateData ConfidentialSecretModel
	var data ConfidentialSecretModel

	resp.Diagnostics.Append(req.State.Get(ctx, &stateData)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if d.DoUpdate(ctx, &stateData, &data, resp) == FlushState {
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	}
}

func (d *ConfidentialAzVaultSecretResource) DoUpdate(ctx context.Context, stateData *ConfidentialSecretModel, planData *ConfidentialSecretModel, resp *resource.UpdateResponse) StateFlushFlag {
	destSecretCoordinate, err := stateData.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("Error getting destination secret coordinate", err.Error())
		return DoNotFlushState
	}

	destSecretCoordinateFromCfg := d.factory.GetDestinationVaultObjectCoordinate(planData.DestinationSecret, "secrets")
	if !destSecretCoordinateFromCfg.SameAs(destSecretCoordinate.AzKeyVaultObjectCoordinate) {
		//resp.Diagnostics.AddError("Value mismatch", fmt.Sprintf("%s != %s", destSecretCoordinate.AzKeyVaultObjectCoordinate.AsString(), destSecretCoordinateFromCfg.AsString()))
		resp.Diagnostics.AddError(
			"Implicit object move",
			"The destination for this confidential secret changed after the secret was created. "+
				"This can happen e.g. when target vault was not explicitly specified. "+
				"Delete this secret instead",
		)
		return DoNotFlushState
	}

	secretClient, err := d.factory.GetSecretsClient(destSecretCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destSecretCoordinate.VaultName, err.Error()))
		return DoNotFlushState
	} else if secretClient == nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return DoNotFlushState
	}

	param := d.convertToUpdateSecretPropertiesParam(planData)
	secretResp, updateErr := secretClient.UpdateSecretProperties(ctx, destSecretCoordinate.Name, destSecretCoordinate.Version, param, nil)

	if updateErr != nil {
		resp.Diagnostics.AddError("Error updating secret properties", updateErr.Error())
		return DoNotFlushState
	}
	planData.Accept(secretResp.Secret)

	return FlushState
}

// Delete Performs DELETE operation on the created secret. The implementation disables the secret version
func (d *ConfidentialAzVaultSecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfidentialSecretModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.SecretVersion.IsUnknown() {
		tflog.Warn(ctx, "Deleting resource that doesn't have recorded versioned coordinate.")
		resp.Diagnostics.AddWarning("incomplete configuration", "secret version is not specified when the resource is being deleted; did it ever exist?")
		return
	}

	destCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("Error getting destination secret coordinate", err.Error())
		return
	}

	secretClient, err := d.factory.GetSecretsClient(destCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destCoordinate.VaultName, err.Error()))
		return
	} else if secretClient == nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return
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
		resp.Diagnostics.AddError("Cannot disable secret version", fmt.Sprintf("Request to disable secret's %s version %s in vault %s failed: %s",
			destCoordinate.Name,
			destCoordinate.Version,
			destCoordinate.VaultName,
			azErr.Error(),
		))
	}
}

// --------------------------------------------------------------------------------
// Factory method

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &ConfidentialAzVaultSecretResource{}

func NewConfidentialAzVaultSecretResource() resource.Resource {
	return &ConfidentialAzVaultSecretResource{}
}
