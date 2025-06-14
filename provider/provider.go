package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/schemasupport"
	tfstringvalidators "github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	tfprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type ObjectHashTracker interface {
	// IsObjectIdTracked Checks if the object Id is tracked
	IsObjectIdTracked(ctx context.Context, id string) (bool, error)

	// TrackObjectId Track object Id in the memory of seeing objects
	TrackObjectId(ctx context.Context, id string) error
}

type OAEPLabelType int

const (
	NoOAEPLabelling OAEPLabelType = iota
	FixedOAEPLabel
	StrictOAEPLabel
)

type AZClientsFactoryImpl struct {
	Credential              azcore.TokenCredential
	DefaultWrappingKey      *core.WrappingKeyCoordinateModel
	DefaultDestinationVault string

	OAEPLabel       []byte
	OAEPEnforcement OAEPLabelType

	secretClients      map[string]*azsecrets.Client
	keysClients        map[string]*azkeys.Client
	certificateClients map[string]*azcertificates.Client

	hashTacker ObjectHashTracker
}

func (cm *AZClientsFactoryImpl) GetDestinationVaultObjectCoordinate(coord core.AzKeyVaultObjectCoordinateModel) core.AzKeyVaultObjectCoordinate {
	vaultName := cm.DefaultDestinationVault
	if len(coord.VaultName.ValueString()) > 0 {
		vaultName = coord.VaultName.ValueString()
	}

	secretName := coord.Name.ValueString()
	return core.AzKeyVaultObjectCoordinate{
		VaultName: vaultName,
		Name:      secretName,
	}
}

func (f *AZClientsFactoryImpl) GetOAEPLabelFor(d core.AzKeyVaultObjectCoordinate) []byte {
	if f.OAEPEnforcement == NoOAEPLabelling {
		return nil
	} else if f.OAEPEnforcement == FixedOAEPLabel {
		return []byte(f.OAEPLabel)
	} else {
		return nil
	}
}

func (f *AZClientsFactoryImpl) GetOAEPLabelForProvider() []byte {
	if f.OAEPEnforcement == NoOAEPLabelling {
		return nil
	} else {
		return []byte(f.OAEPLabel)
	}
}

func (f *AZClientsFactoryImpl) IsObjectIdTracked(ctx context.Context, id string) (bool, error) {
	if f.hashTacker != nil {
		return f.hashTacker.IsObjectIdTracked(ctx, id)
	} else {
		return false, nil
	}
}

func (f *AZClientsFactoryImpl) TrackObjectId(ctx context.Context, id string) error {
	if f.hashTacker != nil {
		return f.hashTacker.TrackObjectId(ctx, id)
	} else {
		return nil
	}
}

var _ core.AZClientsFactory = &AZClientsFactoryImpl{}

func (f *AZClientsFactoryImpl) GetOAEPLabelAsByteSlice() []byte {
	return f.OAEPLabel
}

func (f *AZClientsFactoryImpl) GetMergedWrappingKeyCoordinate(ctx context.Context, param *core.WrappingKeyCoordinateModel, diag diag.Diagnostics) core.WrappingKeyCoordinate {

	base := core.WrappingKeyCoordinate{
		VaultName:  core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.VaultName }, param, f.DefaultWrappingKey),
		KeyName:    core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.KeyName }, param, f.DefaultWrappingKey),
		KeyVersion: core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.KeyVersion }, param, f.DefaultWrappingKey),
		Algorithm:  core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.Algorithm }, param, f.DefaultWrappingKey),
	}

	if base.AddressesKey() {
		if kClient, err := f.GetKeysClient(base.VaultName); err != nil {
			diag.AddError("cannot obtain key client", err.Error())
		} else {
			base.FillDefaults(ctx, kClient, diag)
		}
	} else {
		diag.AddError("incomplete coordinate of a wrapping key", "at least vault and key name are required")
	}

	diag.Append(base.Validate()...)

	return base
}

// GetSecretsClient return (potentially cached) secrets client to connect to the specified
// vault name. The `vaultName` is the (url) name of the vault to have the client connect to
func (f *AZClientsFactoryImpl) GetSecretsClient(vaultName string) (*azsecrets.Client, error) {
	if f.secretClients == nil {
		f.secretClients = map[string]*azsecrets.Client{}
	}

	vaultUrl := fmt.Sprintf("https://%s.vault.azure.net", vaultName)

	if client, ok := f.secretClients[vaultUrl]; ok {
		return client, nil
	}

	client, err := azsecrets.NewClient(vaultUrl, f.Credential, nil)
	if err != nil {
		return nil, err
	}

	f.secretClients[vaultUrl] = client
	return client, nil
}

// GetKeysClient return (potentially cached) secrets client to connect to the specified
// vault name. The `vaultName` is the (url) name of the vault to have the client connect to
func (f *AZClientsFactoryImpl) GetKeysClient(vaultName string) (*azkeys.Client, error) {
	if f.keysClients == nil {
		f.keysClients = map[string]*azkeys.Client{}
	}

	vaultUrl := fmt.Sprintf("https://%s.vault.azure.net", vaultName)

	if client, ok := f.keysClients[vaultUrl]; ok {
		return client, nil
	}

	client, err := azkeys.NewClient(vaultUrl, f.Credential, nil)
	if err != nil {
		return nil, err
	}

	f.keysClients[vaultUrl] = client
	return client, nil
}

// GetCertificateClient return (potentially cached) secrets client to connect to the specified
// vault name. The `vaultName` is the (url) name of the vault to have the client connect to
func (f *AZClientsFactoryImpl) GetCertificateClient(vaultName string) (*azcertificates.Client, error) {
	if f.certificateClients == nil {
		f.certificateClients = map[string]*azcertificates.Client{}
	}

	vaultUrl := fmt.Sprintf("https://%s.vault.azure.net", vaultName)

	if client, ok := f.certificateClients[vaultUrl]; ok {
		return client, nil
	}

	client, err := azcertificates.NewClient(vaultUrl, f.Credential, nil)
	if err != nil {
		return nil, err
	}

	f.certificateClients[vaultUrl] = client
	return client, nil
}

type AZConnectorProviderImpl struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

type FileHashTrackerConfigModel struct {
	FileName types.String `tfsdk:"file_name"`
}

type AZConnectorProviderImplModel struct {
	TenantID                     types.String                     `tfsdk:"tenant_id"`
	SubscriptionID               types.String                     `tfsdk:"subscription_id"`
	ClientID                     types.String                     `tfsdk:"client_id"`
	ClientSecret                 types.String                     `tfsdk:"client_secret"`
	DefaultWrappingKeyCoordinate *core.WrappingKeyCoordinateModel `tfsdk:"default_wrapping_key"`

	DefaultDestinationVaultName types.String                `tfsdk:"default_destination_vault_name"`
	OAEPLabel                   types.String                `tfsdk:"oaep_label"`
	OAEPEnforcement             types.String                `tfsdk:"oaep_enforcement"`
	FileHashTrackerConfig       *FileHashTrackerConfigModel `tfsdk:"file_hash_tracker"`
}

func (pm *AZConnectorProviderImplModel) GetOAEPLabelAsByteSlice() ([]byte, error) {
	v := pm.OAEPLabel.ValueString()
	if len(v) == 0 {
		return nil, nil
	}

	return base64.StdEncoding.DecodeString(v)
}

func (pm *AZConnectorProviderImplModel) SpecifiesCredentialParameters() bool {
	return len(pm.TenantID.ValueString()) > 0 &&
		len(pm.SubscriptionID.ValueString()) > 0 &&
		len(pm.ClientID.ValueString()) > 0 &&
		len(pm.ClientSecret.ValueString()) > 0
}

func (pm *AZConnectorProviderImplModel) GetExplicitCredential() (azcore.TokenCredential, error) {
	return azidentity.NewClientSecretCredential(
		pm.TenantID.ValueString(),
		pm.ClientID.ValueString(),
		pm.ClientSecret.ValueString(),
		nil,
	)
}

func (p *AZConnectorProviderImpl) Metadata(ctx context.Context, req tfprovider.MetadataRequest, resp *tfprovider.MetadataResponse) {
	resp.TypeName = "az-confidential"
	resp.Version = p.version
}

func (p *AZConnectorProviderImpl) Schema(ctx context.Context, req tfprovider.SchemaRequest, resp *tfprovider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "Tenant ID to use",
				Optional:            true,
			},
			"subscription_id": schema.StringAttribute{
				MarkdownDescription: "Subscription ID to use",
				Optional:            true,
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "Client ID to use",
				Optional:            true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "Client secret to use",
				Optional:            true,
			},
			"default_destination_vault_name": schema.StringAttribute{
				MarkdownDescription: "Default destination vault name where decrypted secrets need to be placed",
				Description:         "Default destination vault where decrypted secreted need to be placed",
				Required:            true,
				Validators: []validator.String{
					// A non-empty value must be supplied here.
					tfstringvalidators.LengthAtLeast(1),
				},
			},
			"oaep_label": schema.StringAttribute{
				MarkdownDescription: "OAEP Label to use during the encrypted data unwrapping",
				Description:         "OAEP Label to use use during the encrypted data unwrapping",
				Optional:            true,
				Validators: []validator.String{
					schemasupport.Base64StringValidator{},
				},
			},
			"oaep_enforcement": schema.StringAttribute{
				MarkdownDescription: "OAEP label enforcement; default to strict",
				Description:         "OAEP label enforcement; default to strict",
				Optional:            true,
				Validators: []validator.String{
					tfstringvalidators.OneOf("strict", "fixed", "none"),
				},
			},
			"file_hash_tracker": schema.SingleNestedAttribute{
				MarkdownDescription: "OAEP Label to use during the encrypted data unwrapping",
				Description:         "OAEP Label to use use during the encrypted data unwrapping",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"file_name": schema.StringAttribute{
						MarkdownDescription: "File on a local machine where to track created secrets",
						Description:         "File on a local machine where to track created secrets",
						Required:            true,
					},
				},
			},
			"default_wrapping_key": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"vault_name": schema.StringAttribute{
						Optional:    true,
						Description: "Vault name containing the wrapping key",
					},
					"name": schema.StringAttribute{
						Optional:    true,
						Description: "Name of the wrapping key",
					},
					"version": schema.StringAttribute{
						Optional:    true,
						Description: "Version of the wrapping key to be used for unwrapping operations",
					},
					"algorithm": schema.StringAttribute{
						Optional:    true,
						Description: "Encryption algorithm to be used for unwrapping operations",
					},
				},
				Optional:    true,
				Description: "Default location of the wrapping key",
			},
		},
	}
}

func (p *AZConnectorProviderImpl) DataSources(ctx context.Context) []func() datasource.DataSource {
	tflog.Debug(ctx, "AzConfidential: initializing data sources")
	return []func() datasource.DataSource{
		resources.NewConfidentialPasswordDataSource,
	}
}

func (p *AZConnectorProviderImpl) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewConfidentialAzVaultSecretResource,
		resources.NewConfidentialAzVaultKeyResource,
		resources.NewConfidentialAzVaultCertificateResource,
	}
}

func (p *AZConnectorProviderImpl) ConfigureHashTracker(ctx context.Context, data AZConnectorProviderImplModel) (ObjectHashTracker, error) {
	if data.FileHashTrackerConfig != nil {
		return NewLocalFileTracker(ctx, data.FileHashTrackerConfig.FileName.ValueString())
	} else {
		return nil, nil
	}
}

func (p *AZConnectorProviderImpl) Configure(ctx context.Context, req tfprovider.ConfigureRequest, resp *tfprovider.ConfigureResponse) {
	tflog.Debug(ctx, "AzConfidential: attempting to configure the provider")
	var data AZConnectorProviderImplModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "AzConfidential provider configuration has errors")
		return
	}

	var cred azcore.TokenCredential
	var azCredError error

	if data.SpecifiesCredentialParameters() {
		cred, azCredError = data.GetExplicitCredential()
	} else {
		cred, azCredError = azidentity.NewDefaultAzureCredential(nil)
	}

	if azCredError != nil {
		resp.Diagnostics.AddError("Cannot obtain default Azure credential", fmt.Sprintf("Unable to obtain default Azure credential: %s", azCredError.Error()))
		tflog.Error(ctx, "Unable to obtain default Azure credential")
		return
	}

	oaepLabel, oaepErr := data.GetOAEPLabelAsByteSlice()
	if oaepErr != nil {
		tflog.Error(ctx, "Unable to obtain the OAEP label that must be used")
		resp.Diagnostics.AddError("Invalid OAEP Label (must be base-64)", oaepErr.Error())
		return
	}

	oaepEnforcementLevel := StrictOAEPLabel
	if !data.OAEPEnforcement.IsNull() {
		v := data.OAEPEnforcement.ValueString()
		switch v {
		case "fixed":
			oaepEnforcementLevel = FixedOAEPLabel
		case "none":
			oaepEnforcementLevel = NoOAEPLabelling
		}
	}

	hashTracker, hashTrackerInitErr := p.ConfigureHashTracker(ctx, data)
	if hashTrackerInitErr != nil {
		resp.Diagnostics.AddError("Failed to initialize hash tracker", hashTrackerInitErr.Error())
		return
	}

	tflog.Info(ctx, "AzConfidential provider was able to obtain access token to Azure API")

	factory := &AZClientsFactoryImpl{
		Credential:         cred,
		DefaultWrappingKey: data.DefaultWrappingKeyCoordinate,

		DefaultDestinationVault: data.DefaultDestinationVaultName.ValueString(),
		OAEPLabel:               oaepLabel,
		OAEPEnforcement:         oaepEnforcementLevel,
		hashTacker:              hashTracker,
	}

	resp.DataSourceData = factory
	resp.ResourceData = factory

	tflog.Info(ctx, "AzConfidential provider has been configured")
}

func (p *AZConnectorProviderImpl) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

var _ tfprovider.Provider = &AZConnectorProviderImpl{}

func New(version string) func() tfprovider.Provider {
	return func() tfprovider.Provider {
		return &AZConnectorProviderImpl{
			version: version,
		}
	}
}
