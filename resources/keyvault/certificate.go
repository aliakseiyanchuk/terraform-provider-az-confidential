package keyvault

import (
	"context"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
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
	"software.sslmate.com/src/go-pkcs12"
)

type CertificateModel struct {
	resources.WrappedAzKeyVaultObjectConfidentialMaterialModel
	VersionlessId       types.String `tfsdk:"versionless_id"`
	SecretId            types.String `tfsdk:"secret_id"`
	VersionlessSecretId types.String `tfsdk:"versionless_secret_id"`

	DestinationCert    core.AzKeyVaultObjectCoordinateModel `tfsdk:"destination_certificate"`
	CertificateVersion types.String                         `tfsdk:"version"`

	Thumbprint            types.String `tfsdk:"thumbprint"`
	CertificateData       types.String `tfsdk:"certificate_data"`
	CertificateDataBase64 types.String `tfsdk:"certificate_data_base64"`
}

func (cm *CertificateModel) Accept(cert azcertificates.Certificate) {
	cm.AssignId(cert)

	tfSecretIdVal := types.StringNull()
	tfVersionlessSecretIdVal := types.StringNull()

	if cert.Attributes != nil {
		cm.NotBefore = core.FormatTime(cert.Attributes.NotBefore)
		cm.NotAfter = core.FormatTime(cert.Attributes.Expires)

		cm.ConvertAzBool(cert.Attributes.Enabled, &cm.Enabled)
	}

	if cert.SID != nil {
		azIdStr := string(*cert.SID)
		tfSecretIdVal = types.StringValue(azIdStr)

		coord := core.AzKeyVaultObjectVersionedCoordinate{}
		if err := coord.FromId(azIdStr); err == nil {
			tfVersionlessSecretIdVal = types.StringValue(coord.VersionlessId())
		}
	}

	cm.SecretId = tfSecretIdVal
	cm.VersionlessSecretId = tfVersionlessSecretIdVal
	cm.Thumbprint = types.StringValue(hex.EncodeToString(cert.X509Thumbprint))

	cm.CertificateData = types.StringValue(hex.EncodeToString(cert.CER))
	cm.CertificateDataBase64 = types.StringValue(base64.StdEncoding.EncodeToString(cert.CER))
}

func (cm *CertificateModel) AssignId(cert azcertificates.Certificate) {
	tfIdVal := types.StringNull()
	tfVersionVal := types.StringNull()
	tfVersionlessIdVal := types.StringNull()

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

	cm.Id = tfIdVal
	cm.CertificateVersion = tfVersionVal
	cm.VersionlessId = tfVersionlessIdVal
}

func (d *CertificateModel) ConvertToImportCertParam() azcertificates.ImportCertificateParameters {
	certAttr := azcertificates.CertificateAttributes{
		NotBefore: d.NotBeforeDateAtPtr(),
		Expires:   d.NotAfterDateAtPtr(),
		Enabled:   d.Enabled.ValueBoolPointer(),
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
		Tags:     d.TagsAsPtr(),
	}

	return rv
}

func (d *CertificateModel) ConvertToUpdateCertParam() azcertificates.UpdateCertificateParameters {
	certAttr := azcertificates.CertificateAttributes{
		NotBefore: d.NotBeforeDateAtPtr(),
		Expires:   d.NotAfterDateAtPtr(),
		Enabled:   d.Enabled.ValueBoolPointer(),
	}
	rv := azcertificates.UpdateCertificateParameters{
		CertificateAttributes: &certAttr,
		Tags:                  d.TagsAsPtr(),
	}

	return rv
}

//go:embed certificate.md
var certificateResourceMarkdownDescription string

type AzKeyVaultCertificateResourceSpecializer struct {
	factory core.AZClientsFactory
}

func (a *AzKeyVaultCertificateResourceSpecializer) SetFactory(factory core.AZClientsFactory) {
	a.factory = factory
}

func (a *AzKeyVaultCertificateResourceSpecializer) NewTerraformModel() CertificateModel {
	return CertificateModel{}
}

func (a *AzKeyVaultCertificateResourceSpecializer) ConvertToTerraform(azObj azcertificates.Certificate, tfModel *CertificateModel) diag.Diagnostics {
	tfModel.Accept(azObj)
	return diag.Diagnostics{}
}

func (a *AzKeyVaultCertificateResourceSpecializer) GetConfidentialMaterialFrom(mdl CertificateModel) resources.ConfidentialMaterialModel {
	return mdl.ConfidentialMaterialModel
}

func (a *AzKeyVaultCertificateResourceSpecializer) GetSupportedConfidentialMaterialTypes() []string {
	return []string{CertificateObjectType}
}

func (a *AzKeyVaultCertificateResourceSpecializer) CheckPlacement(ctx context.Context, pc []core.ProviderConstraint, pl []core.PlacementConstraint, tfModel *CertificateModel) diag.Diagnostics {
	rv := diag.Diagnostics{}

	destKeyCoordinate := a.factory.GetDestinationVaultObjectCoordinate(tfModel.DestinationCert, "certificates")

	a.factory.EnsureCanPlaceLabelledObjectAt(ctx, pc, pl, "certificate", &destKeyCoordinate, &rv)
	return rv
}

func (a *AzKeyVaultCertificateResourceSpecializer) DoRead(ctx context.Context, data *CertificateModel) (azcertificates.Certificate, resources.ResourceExistenceCheck, diag.Diagnostics) {
	rv := diag.Diagnostics{}
	// The key version was never created; nothing needs to be read here.
	if data.Id.IsUnknown() {
		return azcertificates.Certificate{}, resources.ResourceNotYetCreated, rv
	}

	destCertCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("Cannot establish reference to the created certificate version", err.Error())
		return azcertificates.Certificate{}, resources.ResourceCheckError, rv
	}

	certClient, err := a.factory.GetCertificateClient(destCertCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire certificates client", fmt.Sprintf("Cannot acquire cert client to vault %s: %s", destCertCoordinate.VaultName, err.Error()))
		return azcertificates.Certificate{}, resources.ResourceCheckError, rv
	} else if certClient == nil {
		rv.AddError("Cannot acquire certificates client", "Cert client returned is nil")
		return azcertificates.Certificate{}, resources.ResourceCheckError, rv
	}

	certState, err := certClient.GetCertificate(ctx, destCertCoordinate.Name, destCertCoordinate.Version, nil)
	if err != nil {
		if core.IsResourceNotFoundError(err) {
			if a.factory.IsObjectTrackingEnabled() {
				rv.AddWarning(
					"Certificate removed from key vault",
					fmt.Sprintf("Certificate %s version %s is no longer in vault %s. The provider tracks confidential objects; creating this certificate again will be rejected as duplicate. If creathing this certificate again is intentional, re-encrypt ciphertext.",
						destCertCoordinate.Name,
						destCertCoordinate.Version,
						destCertCoordinate.VaultName,
					),
				)
			}

			return azcertificates.Certificate{}, resources.ResourceNotFound, rv
		} else {
			rv.AddError("Cannot read certificate", fmt.Sprintf("Cannot acquire certificatge %s version %s from vault %s: %s",
				destCertCoordinate.Name,
				destCertCoordinate.Version,
				destCertCoordinate.VaultName,
				err.Error()))
			return azcertificates.Certificate{}, resources.ResourceCheckError, rv
		}
	}

	return certState.Certificate, resources.ResourceExists, rv
}

func (a *AzKeyVaultCertificateResourceSpecializer) DoCreate(ctx context.Context, data *CertificateModel, confidentialData core.ConfidentialCertificateData) (azcertificates.Certificate, diag.Diagnostics) {
	rv := diag.Diagnostics{}
	if len(confidentialData.GetCertificateData()) == 0 {
		rv.AddError("Missing payload", "Unwrapped payload does not contain expected content")
		return azcertificates.Certificate{}, rv
	}

	params := data.ConvertToImportCertParam()
	params.Base64EncodedCertificate = core.ConvertBytesAsBase64StringPtr(confidentialData.GetCertificateData)
	params.CertificatePolicy.SecretProperties.ContentType = core.ConvertToPrt(confidentialData.GetCertificateDataFormat)
	params.Password = core.ConvertToPrt(confidentialData.GetCertificateDataPassword)

	destSecretCoordinate := a.factory.GetDestinationVaultObjectCoordinate(data.DestinationCert, "certificates")

	certClient, secErr := a.factory.GetCertificateClient(destSecretCoordinate.VaultName)
	if secErr != nil {
		rv.AddError("Error acquiring certificates client", secErr.Error())
		return azcertificates.Certificate{}, rv
	} else if certClient == nil {
		rv.AddError("Az certificates vault keys client cannot be retrieved", "Nil client returned while no error was raised. This is a provider bug. Please report this")
		return azcertificates.Certificate{}, rv
	}

	setResp, setErr := certClient.ImportCertificate(ctx, destSecretCoordinate.Name, params, nil)
	if setErr != nil {
		rv.AddError("Certificate import failed", setErr.Error())
		return azcertificates.Certificate{}, rv
	} else {
		return setResp.Certificate, nil
	}
}

func (a *AzKeyVaultCertificateResourceSpecializer) DoUpdate(ctx context.Context, planData *CertificateModel) (azcertificates.Certificate, diag.Diagnostics) {

	tflog.Info(ctx, fmt.Sprintf("Available object Id: %s", planData.Id.ValueString()))

	rv := diag.Diagnostics{}

	destCertCoordinate, err := planData.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("Error getting previously created certificate coordinate", err.Error())
		return azcertificates.Certificate{}, rv
	}

	destCertCoordinateFromCfg := a.factory.GetDestinationVaultObjectCoordinate(planData.DestinationCert, "certificates")
	if !destCertCoordinateFromCfg.SameAs(destCertCoordinate.AzKeyVaultObjectCoordinate) {
		rv.AddError(
			"Implicit object move",
			"The destination for this confidential certificate changed after the certificate was created. "+
				"This can happen e.g. when target vault was not explicitly specified. "+
				"Delete this certificate instead",
		)
		return azcertificates.Certificate{}, rv
	}

	certClient, err := a.factory.GetCertificateClient(destCertCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire cert client", fmt.Sprintf("Cannot acquire secret client to vault %s: %s", destCertCoordinate.VaultName, err.Error()))
		return azcertificates.Certificate{}, rv
	} else if certClient == nil {
		rv.AddError("Cannot acquire cert client", "Cert client returned is nil")
		return azcertificates.Certificate{}, rv
	}

	param := planData.ConvertToUpdateCertParam()
	tflog.Info(ctx, fmt.Sprintf("Updating with %d tags", len(param.Tags)))

	updateResponse, updateErr := certClient.UpdateCertificate(ctx, destCertCoordinate.Name, destCertCoordinate.Version, param, nil)

	if updateErr != nil {
		rv.AddError("Error updating certificate properties", updateErr.Error())
		return azcertificates.Certificate{}, rv
	} else {
		return updateResponse.Certificate, rv
	}
}

func (a *AzKeyVaultCertificateResourceSpecializer) DoDelete(ctx context.Context, data *CertificateModel) diag.Diagnostics {
	rv := diag.Diagnostics{}

	destCoordinate, err := data.GetDestinationCoordinateFromId()
	if err != nil {
		rv.AddError("Error getting previously created certificate coordinate", err.Error())
		return rv
	}

	certsClient, err := a.factory.GetCertificateClient(destCoordinate.VaultName)
	if err != nil {
		rv.AddError("Cannot acquire certificate client", fmt.Sprintf("Cannot acquire certificatge client to vault %s: %s", destCoordinate.VaultName, err.Error()))
		return rv
	} else if certsClient == nil {
		rv.AddError("Cannot acquire certificate client", "Certificate client returned is nil")
		return rv
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
		rv.AddError("Cannot disable cert version", fmt.Sprintf("Request to disable cert's %s version %s in vault %s failed: %s",
			destCoordinate.Name,
			destCoordinate.Version,
			destCoordinate.VaultName,
			azErr.Error(),
		))
	}

	return rv
}

func (a *AzKeyVaultCertificateResourceSpecializer) GetJsonDataImporter() core.ObjectJsonImportSupport[core.ConfidentialCertificateData] {
	return core.NewVersionedKeyVaultCertificateConfidentialDataHelper(CertificateObjectType)
}

const CertificateObjectType = "kv/certificate"

func NewCertificateResource() resource.Resource {
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

	resourceSchema := schema.Schema{
		Description:         "Create a certificate in Azure KeyVault without revealing its value in state",
		MarkdownDescription: certificateResourceMarkdownDescription,

		Attributes: resources.WrappedAzKeyVaultObjectConfidentialMaterialModelSchema(specificAttrs),
	}

	keyVaultCertSpecializer := &AzKeyVaultCertificateResourceSpecializer{}

	return &resources.ConfidentialGenericResource[CertificateModel, int, core.ConfidentialCertificateData, azcertificates.Certificate]{
		Specializer:    keyVaultCertSpecializer,
		ImmutableRU:    keyVaultCertSpecializer,
		ResourceName:   "certificate",
		ResourceSchema: resourceSchema,
	}
}

type CertificateDataFunctionParameter struct {
	Certificate types.String `tfsdk:"certificate"`
	Password    types.String `tfsdk:"password"`
}

const (
	CertFormatPem    = "application/x-pem-file"
	CertFormatPkcs12 = "application/x-pkcs12"
)

type AzKvCertificateParamValidator struct{}

func (vld *AzKvCertificateParamValidator) ValidateParameterObject(ctx context.Context, req function.ObjectParameterValidatorRequest, res *function.ObjectParameterValidatorResponse) {
	v := CertificateDataFunctionParameter{}

	req.Value.As(ctx, &v, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})

	if len(v.Certificate.ValueString()) == 0 {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Certificate data value must be specified"))
	}

	// The input must be either PEM encoded, otherwise it must be a valid b64
	if !core.IsPEMEncoded([]byte(v.Certificate.ValueString())) {
		if _, b64Decode := base64.StdEncoding.DecodeString(v.Certificate.ValueString()); b64Decode != nil {
			res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError("Certificate data value must be PEM encoded, or at least Base64-encoded"))
		}
	}
}

func AcquireCertificateData(certData []byte, password string) (core.ConfidentialCertificateData, error) {
	confData := core.ConfidentialCertConfidentialDataStruct{
		CertificateData:         certData,
		CertificateDataFormat:   "application/unknown",
		CertificateDataPassword: "",
	}

	// Acquire the key
	if core.IsPEMEncoded(certData) {
		blocks, blockErr := core.ParsePEMBlocks(certData)
		confData.CertificateDataFormat = CertFormatPem

		if blockErr != nil {
			return nil, fmt.Errorf("cannot parse PEM blocks: %s", blockErr.Error())
		}

		if len(core.FindCertificateBlocks(blocks)) == 0 {
			return nil, errors.New("input does not contain any certificate blocks")
		}

		privateKeyBlock := core.FindPrivateKeyBlock(blocks)
		if privateKeyBlock == nil {
			return nil, errors.New("input does not contain any private keys")
		}

		if privateKeyBlock.Type == "ENCRYPTED PRIVATE KEY" {
			if len(password) == 0 {
				return nil, errors.New("password is required where private key is encrypted")
			}

			// Try to decrypt the PEM key; to ensure that the password is correct
			_, loadErr := core.PrivateKeyFromEncryptedBlock(blocks[0], password)
			if loadErr != nil {
				return nil, loadErr
			} else {
				confData.CertificateDataPassword = password
			}
		} else if privateKeyBlock.Type != "PRIVATE KEY" {
			return nil, errors.New("input certificate data does not contain private key")
		}
	} else {
		confData.CertificateDataFormat = CertFormatPkcs12

		if _, _, pwdErr := pkcs12.Decode(confData.GetCertificateData(), password); pwdErr != nil {
			return nil, fmt.Errorf("cannot load certificate from PKCS12/PFX bag; %s", pwdErr.Error())
		} else {
			confData.CertificateDataPassword = password
		}
	}

	return &confData, nil
}

func CreateCertificateEncryptedMessage(certData core.ConfidentialCertificateData, coord *core.AzKeyVaultObjectCoordinate, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, core.SecondaryProtectionParameters, error) {
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper(CertificateObjectType)

	if coord != nil {
		md.PlacementConstraints = []core.PlacementConstraint{core.PlacementConstraint(coord.GetLabel())}
	}

	_ = helper.CreateConfidentialCertificateData(
		certData.GetCertificateData(),
		certData.GetCertificateDataFormat(),
		certData.GetCertificateDataPassword(),
		md,
	)
	em, err := helper.ToEncryptedMessage(pubKey)
	return em, md, err
}

func DecryptCertificateMessage(em core.EncryptedMessage, decrypted core.RSADecrypter) (core.ConfidentialDataJsonHeader, core.ConfidentialCertificateData, error) {
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper(CertificateObjectType)

	err := helper.FromEncryptedMessage(em, decrypted)
	return helper.Header, helper.KnowValue, err
}

func NewCertificateEncryptorFunction() function.Function {
	rv := resources.FunctionTemplate[CertificateDataFunctionParameter, resources.ResourceProtectionParams, core.AzKeyVaultObjectCoordinateModel]{
		Name:                "encrypt_keyvault_certificate",
		Summary:             "Produces a ciphertext string suitable for use with az-confidential_certificate resource",
		MarkdownDescription: "Encrypts a certificate data without the use of the `tfgen` tool",

		DataParameter: function.ObjectParameter{
			Name:        "certificate_data",
			Description: "Certificate data to be encrypted",

			AttributeTypes: map[string]attr.Type{
				"certificate": types.StringType,
				"password":    types.StringType,
			},

			Validators: []function.ObjectParameterValidator{
				&AzKvCertificateParamValidator{},
			},
		},
		ProtectionParameterSupplier: func() resources.ResourceProtectionParams { return resources.ResourceProtectionParams{} },
		DestinationParameter: function.ObjectParameter{
			Name:               "destination_certificate",
			Description:        "Destination vault and certificate name",
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
		ConfidentialModelSupplier: func() CertificateDataFunctionParameter { return CertificateDataFunctionParameter{} },
		DestinationModelSupplier: func() *core.AzKeyVaultObjectCoordinateModel {
			var ptr *core.AzKeyVaultObjectCoordinateModel
			return ptr
		},

		CreatEncryptedMessage: func(confidentialModel CertificateDataFunctionParameter, dest *core.AzKeyVaultObjectCoordinateModel, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, error) {
			var coord *core.AzKeyVaultObjectCoordinate
			if dest != nil {
				coord = &core.AzKeyVaultObjectCoordinate{
					VaultName: dest.VaultName.ValueString(),
					Name:      dest.Name.ValueString(),
					Type:      "certificates",
				}

			}

			var certByte []byte
			if b64, b64Err := base64.StdEncoding.DecodeString(confidentialModel.Certificate.ValueString()); b64Err == nil {
				certByte = b64
			} else {
				certByte = []byte(confidentialModel.Certificate.ValueString())
			}
			password := confidentialModel.Password.ValueString()

			certData, acqErr := AcquireCertificateData(certByte, password)
			if acqErr != nil {
				return core.EncryptedMessage{}, acqErr
			}

			// Produce ciphertext
			em, _, emErr := CreateCertificateEncryptedMessage(certData, coord, md, pubKey)
			return em, emErr
		},
	}

	return &rv
}
