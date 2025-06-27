package resources

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type ConfidentialCertificateModel struct {
	WrappedAzKeyVaultObjectConfidentialMaterialModel
	VersionlessId       types.String `tfsdk:"versionless_id"`
	SecretId            types.String `tfsdk:"secret_id"`
	VersionlessSecretId types.String `tfsdk:"versionless_secret_id"`

	DestinationCert    core.AzKeyVaultObjectCoordinateModel `tfsdk:"destination_certificate"`
	CertificateVersion types.String                         `tfsdk:"version"`

	Thumbprint            types.String `tfsdk:"thumbprint"`
	CertificateData       types.String `tfsdk:"certificate_data"`
	CertificateDataBase64 types.String `tfsdk:"certificate_data_base64"`
}

func (cm *ConfidentialCertificateModel) Accept(cert azcertificates.Certificate) {
	tfVersionVal := types.StringNull()
	tfVersionlessIdVal := types.StringNull()
	tfSecretIdVal := types.StringNull()
	tfVersionlessSecretIdVal := types.StringNull()
	tfIdVal := types.StringNull()

	if cert.Attributes != nil {
		cm.NotBefore = core.FormatTime(cert.Attributes.NotBefore)
		cm.NotAfter = core.FormatTime(cert.Attributes.Expires)

		if cert.Attributes.Enabled != nil {
			cm.Enabled = types.BoolValue(*cert.Attributes.Enabled)
		}
	}

	if cert.ID != nil {
		azIdStr := string(*cert.ID)

		tfIdVal = types.StringValue(azIdStr)
		coord := core.AzKeyVaultObjectVersionedCoordinate{}

		// Error on parsing responses returned from Azure is extremely unlikely;
		// therefore, here's only null protection. The else condition should never
		// really trigger.
		if err := coord.FromId(azIdStr); err == nil {
			tfVersionlessIdVal = types.StringValue(coord.VersionlessId())
		}

		tfVersionVal = types.StringValue(cert.ID.Version())
	}

	if cert.SID != nil {
		azIdStr := string(*cert.SID)
		tfSecretIdVal = types.StringValue(azIdStr)

		coord := core.AzKeyVaultObjectVersionedCoordinate{}
		if err := coord.FromId(azIdStr); err == nil {
			tfVersionlessSecretIdVal = types.StringValue(coord.VersionlessId())
		}
	}

	cm.Id = tfIdVal
	cm.VersionlessId = tfVersionlessIdVal
	cm.SecretId = tfSecretIdVal
	cm.VersionlessSecretId = tfVersionlessSecretIdVal
	cm.CertificateVersion = tfVersionVal
	cm.Thumbprint = types.StringValue(hex.EncodeToString(cert.X509Thumbprint))

	cm.CertificateData = types.StringValue(hex.EncodeToString(cert.CER))
	cm.CertificateDataBase64 = types.StringValue(base64.StdEncoding.EncodeToString(cert.CER))
}

type ConfidentialAzVaultCertificateResource struct {
	ConfidentialResourceBase
}

func (d *ConfidentialAzVaultCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

//go:embed confidential_certificate.md
var certificateResourceMarkdownDescription string

func (d *ConfidentialAzVaultCertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	specificAttrs := map[string]schema.Attribute{
		"versionless_id": schema.StringAttribute{
			Computed: true,
		},
		"secret_id": schema.StringAttribute{
			Computed: true,
		},
		"versionless_secret_id": schema.StringAttribute{
			Computed: true,
		},
		"version": schema.StringAttribute{
			Computed: true,
		},
		"thumbprint": schema.StringAttribute{
			Computed: true,
		},
		"certificate_data": schema.StringAttribute{
			Computed: true,
		},
		"certificate_data_base64": schema.StringAttribute{
			Computed: true,
		},
		"destination_certificate": schema.SingleNestedAttribute{
			Required:            true,
			MarkdownDescription: "Specification of a vault where this certificate needs to be stored",
			Attributes: map[string]schema.Attribute{
				"vault_name": schema.StringAttribute{
					Optional:    true,
					Description: "Vault where the certificate needs to be stored. If omitted, defaults to the vault containing the wrapping key",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
				"name": schema.StringAttribute{
					Optional:    false,
					Required:    true,
					Description: "Name of the certificate to store",
					PlanModifiers: []planmodifier.String{
						stringplanmodifier.RequiresReplace(),
					},
				},
			},
		},
	}

	resp.Schema = schema.Schema{
		Description:         "Create a certificate in Azure KeyVault without revealing its value in state",
		MarkdownDescription: certificateResourceMarkdownDescription,

		Attributes: WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(specificAttrs),
	}
}

func (d *ConfidentialAzVaultCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfidentialCertificateModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The key version was never created; nothing needs to be read here.
	if data.CertificateVersion.IsUnknown() {
		return
	}

	destSecretCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("cannot establish reference to the created certificate version", err.Error())
		return
	}

	certClient, err := d.factory.GetCertificateClient(destSecretCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire cert client", fmt.Sprintf("Cannot acquire cert client to vault %s: %s", destSecretCoordinate.VaultName, err.Error()))
		return
	} else if certClient == nil {
		resp.Diagnostics.AddError("Cannot acquire cert client", "Cert client returned is nil")
		return
	}

	certState, err := certClient.GetCertificate(ctx, destSecretCoordinate.Name, destSecretCoordinate.Version, nil)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read key", fmt.Sprintf("Cannot acquire key %s version %s from vault %s: %s",
			destSecretCoordinate.Name,
			destSecretCoordinate.Version,
			destSecretCoordinate.VaultName,
			err.Error()))
		return
	}
	if certState.ID == nil {
		resp.Diagnostics.AddWarning(
			"Certificate removed outside of Terraform control",
			fmt.Sprintf("Aecret %s version %s from vault %s has been removed outside of Terraform control",
				destSecretCoordinate.Name,
				destSecretCoordinate.Version,
				destSecretCoordinate.Version),
		)
		return
	}

	data.Accept(certState.Certificate)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *ConfidentialAzVaultCertificateResource) convertToImportCertParam(data *ConfidentialCertificateModel) azcertificates.ImportCertificateParameters {
	certAttr := azcertificates.CertificateAttributes{
		NotBefore: data.NotBeforeDateAtPtr(),
		Expires:   data.NotAfterDateAtPtr(),
		Enabled:   data.Enabled.ValueBoolPointer(),
	}

	// Question: what to do with DER-encoded certificates?
	// May need to be set to:
	//application/x-pem-file for .pem
	//application/x-pkcs12 for .p12 .pfx
	rv := azcertificates.ImportCertificateParameters{
		CertificateAttributes: &certAttr,
		CertificatePolicy: &azcertificates.CertificatePolicy{
			SecretProperties: &azcertificates.SecretProperties{
				ContentType: to.Ptr("application/x-pem-file"),
			},
		},
		Password: to.Ptr(""),
		Tags:     data.TagsAsPtr(),
	}

	return rv
}

func (d *ConfidentialAzVaultCertificateResource) convertToUpdateCertParam(data *ConfidentialCertificateModel) azcertificates.UpdateCertificateParameters {
	certAttr := azcertificates.CertificateAttributes{
		NotBefore: data.NotBeforeDateAtPtr(),
		Expires:   data.NotAfterDateAtPtr(),
		Enabled:   data.Enabled.ValueBoolPointer(),
	}
	rv := azcertificates.UpdateCertificateParameters{
		CertificateAttributes: &certAttr,
		Tags:                  data.TagsAsPtr(),
	}

	return rv
}

func (d *ConfidentialAzVaultCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfidentialCertificateModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	confidentialData := d.UnwrapEncryptedConfidentialData(ctx, data.ConfidentialMaterialModel, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if confidentialData.Type != "certificate" {
		resp.Diagnostics.AddError("Unexpected object type", fmt.Sprintf("Expected 'certificate', got '%s'", confidentialData.Type))
		return
	}

	if len(confidentialData.BinaryData) == 0 {
		resp.Diagnostics.AddError("Missing payload", "Unwrapped payload does not contain expected content")
		return
	}

	destSecretCoordinate := d.factory.GetDestinationVaultObjectCoordinate(data.DestinationCert, "certificates")

	d.factory.EnsureCanPlace(ctx, confidentialData, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "checking possibility to place this object raised an error")
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Will import certificate into %s/%s vault/certficiate", data.DestinationCert.VaultName, data.DestinationCert.Name))

	certClient, secErr := d.factory.GetCertificateClient(destSecretCoordinate.VaultName)
	if secErr != nil {
		resp.Diagnostics.AddError("Error acquiring secret client", secErr.Error())
		return
	}

	params := d.convertToImportCertParam(&data)
	params.Base64EncodedCertificate = confidentialData.PayloadAsB64Ptr()

	tflog.Trace(ctx, *params.Base64EncodedCertificate)

	setResp, setErr := certClient.ImportCertificate(ctx, destSecretCoordinate.Name, params, nil)
	if setErr != nil {
		resp.Diagnostics.AddError("Error setting secret", setErr.Error())
		return
	}

	data.Accept(setResp.Certificate)
	d.FlushState(ctx, confidentialData.Uuid, &data, resp)
}

func (d *ConfidentialAzVaultCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var stateData ConfidentialCertificateModel
	var data ConfidentialCertificateModel

	resp.Diagnostics.Append(req.State.Get(ctx, &stateData)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if d.DoUpdate(ctx, &stateData, &data, resp) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *ConfidentialAzVaultCertificateResource) DoUpdate(ctx context.Context, stateData *ConfidentialCertificateModel, planData *ConfidentialCertificateModel, resp *resource.UpdateResponse) StateFlushFlag {
	tflog.Info(ctx, fmt.Sprintf("Available object Id: %s", stateData.Id.ValueString()))

	destCertCoordinate, err := stateData.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("Error getting destination secret coordinate", err.Error())
		return DoNotFlushState
	}

	destCertCoordinateFromCfg := d.factory.GetDestinationVaultObjectCoordinate(planData.DestinationCert, "certificates")
	if !destCertCoordinateFromCfg.SameAs(destCertCoordinate.AzKeyVaultObjectCoordinate) {
		resp.Diagnostics.AddError(
			"Implicit object move",
			"The destination for this confidential certificate changed after the certificate was created. "+
				"This can happen e.g. when target vault was not explicitly specified. "+
				"Delete this certificate instead",
		)
		return DoNotFlushState
	}

	certClient, err := d.factory.GetCertificateClient(destCertCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire cert client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destCertCoordinate.VaultName, err.Error()))
		return DoNotFlushState
	} else if certClient == nil {
		resp.Diagnostics.AddError("Cannot acquire cert client", "Cert client returned is nil")
		return DoNotFlushState
	}

	param := d.convertToUpdateCertParam(planData)
	tflog.Info(ctx, fmt.Sprintf("Updating with %d tags", len(param.Tags)))

	updateResponse, updateErr := certClient.UpdateCertificate(ctx, destCertCoordinate.Name, destCertCoordinate.Version, param, nil)

	if updateErr != nil {
		resp.Diagnostics.AddError("Error updating secret properties", updateErr.Error())
		return DoNotFlushState
	}

	planData.Accept(updateResponse.Certificate)
	return FlushState
}

// Delete Performs DELETE operation on the created secret. The implementation disables the secret version
func (d *ConfidentialAzVaultCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfidentialCertificateModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.CertificateVersion.IsUnknown() {
		tflog.Warn(ctx, "Deleting resource that doesn't have recorded versioned coordinate.")
		return
	}

	destCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		resp.Diagnostics.AddError("Error getting destination secret coordinate", err.Error())
		return
	}

	certsClient, err := d.factory.GetCertificateClient(destCoordinate.VaultName)
	if err != nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destCoordinate.VaultName, err.Error()))
		return
	} else if certsClient == nil {
		resp.Diagnostics.AddError("Cannot acquire secret client", "Secrets client returned is nil")
		return
	}

	enabledVal := false

	_, azErr := certsClient.UpdateCertificate(ctx,
		destCoordinate.Name,
		destCoordinate.Version,
		azcertificates.UpdateCertificateParameters{
			CertificateAttributes: &azcertificates.CertificateAttributes{
				Enabled: &enabledVal,
			},
		},
		nil,
	)

	if azErr != nil {
		resp.Diagnostics.AddError("Cannot disable cert version", fmt.Sprintf("Request to disable cert's %s version %s in vault %s failed: %s",
			destCoordinate.Name,
			destCoordinate.Version,
			destCoordinate.VaultName,
			azErr.Error(),
		))
	}
}

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &ConfidentialAzVaultCertificateResource{}

func NewConfidentialAzVaultCertificateResource() resource.Resource {
	return &ConfidentialAzVaultCertificateResource{}
}
