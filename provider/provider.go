package provider

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/hashicorp/terraform-plugin-framework-validators/providervalidator"
	tfsetvalidators "github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	tfstringvalidators "github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
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

type CachedAzClientsSupplier struct {
	Credential azcore.TokenCredential

	apimSubscriptionClients map[string]*armapimanagement.SubscriptionClient
	apimNamedValueClients   map[string]core.ApimNamedValueClientAbstraction
	secretClients           map[string]*azsecrets.Client
	keysClients             map[string]*azkeys.Client
	certificateClients      map[string]*azcertificates.Client

	keysCache map[string]core.WrappingKeyCoordinate
}

func (css *CachedAzClientsSupplier) GetApimNamedValueClient(subscriptionId string) (core.ApimNamedValueClientAbstraction, error) {
	if css.apimNamedValueClients == nil {
		css.apimNamedValueClients = map[string]core.ApimNamedValueClientAbstraction{}
	}

	if client, ok := css.apimNamedValueClients[subscriptionId]; ok {
		return client, nil
	}

	client, err := armapimanagement.NewNamedValueClient(subscriptionId, css.Credential, nil)
	if err != nil {
		return nil, err
	}

	wrappedClient := ApimNamedValueClientAbstractionWrapper{
		client: client,
	}

	css.apimNamedValueClients[subscriptionId] = &wrappedClient
	return &wrappedClient, nil
}

func (css *CachedAzClientsSupplier) GetApimSubscriptionClient(subscriptionId string) (core.ApimSubscriptionClientAbstraction, error) {
	if css.apimSubscriptionClients == nil {
		css.apimSubscriptionClients = map[string]*armapimanagement.SubscriptionClient{}
	}

	if client, ok := css.apimSubscriptionClients[subscriptionId]; ok {
		return client, nil
	}

	client, err := armapimanagement.NewSubscriptionClient(subscriptionId, css.Credential, nil)
	if err != nil {
		return nil, err
	}
	css.apimSubscriptionClients[subscriptionId] = client
	return client, nil
}

// GetSecretsClient return (potentially cached) secrets client to connect to the specified
// vault name. The `vaultName` is the (url) name of the vault to have the client connected to
func (ccs *CachedAzClientsSupplier) GetSecretsClient(vaultName string) (core.AzSecretsClientAbstraction, error) {
	if ccs.secretClients == nil {
		ccs.secretClients = map[string]*azsecrets.Client{}
	}

	vaultUrl := fmt.Sprintf("https://%s.vault.azure.net", vaultName)

	if client, ok := ccs.secretClients[vaultUrl]; ok {
		return client, nil
	}

	client, err := azsecrets.NewClient(vaultUrl, ccs.Credential, nil)
	if err != nil {
		return nil, err
	}

	ccs.secretClients[vaultUrl] = client
	return client, nil
}

// GetKeysClient return (potentially cached) keys client to connect to the specified
// vault name. The `vaultName` is the (url) name of the vault to have the client connect to
func (ccs *CachedAzClientsSupplier) GetKeysClient(vaultName string) (core.AzKeyClientAbstraction, error) {
	if ccs.keysClients == nil {
		ccs.keysClients = map[string]*azkeys.Client{}
	}

	vaultUrl := fmt.Sprintf("https://%s.vault.azure.net", vaultName)

	if client, ok := ccs.keysClients[vaultUrl]; ok {
		return client, nil
	}

	client, err := azkeys.NewClient(vaultUrl, ccs.Credential, nil)
	if err != nil {
		return nil, err
	}

	ccs.keysClients[vaultUrl] = client
	return client, nil
}

// GetCertificateClient return (potentially cached) secrets client to connect to the specified
// vault name. The `vaultName` is the (url) name of the vault to have the client connect to
func (ccs *CachedAzClientsSupplier) GetCertificateClient(vaultName string) (core.AzCertificateClientAbstraction, error) {
	if ccs.certificateClients == nil {
		ccs.certificateClients = map[string]*azcertificates.Client{}
	}

	vaultUrl := fmt.Sprintf("https://%s.vault.azure.net", vaultName)

	if client, ok := ccs.certificateClients[vaultUrl]; ok {
		return client, nil
	}

	client, err := azcertificates.NewClient(vaultUrl, ccs.Credential, nil)
	if err != nil {
		return nil, err
	}

	ccs.certificateClients[vaultUrl] = client
	return client, nil
}

func (ccs *CachedAzClientsSupplier) CacheWrappingKeyCoordinate(cacheKey string, coordinate core.WrappingKeyCoordinate) {
	if ccs.keysCache == nil {
		ccs.keysCache = map[string]core.WrappingKeyCoordinate{}
	}

	ccs.keysCache[cacheKey] = coordinate
}

// --------------------------------------------------------------------------------
// AzClientsFactory

// AZClientsFactoryImpl Factory implementation
type AZClientsFactoryImpl struct {
	CachedAzClientsSupplier

	DisallowResourceSpecifiedWrappingKey bool
	DefaultWrappingKey                   *core.WrappingKeyCoordinateModel
	DefaultDestinationVault              string
	DefaultAzSubscriptionId              string

	ProviderLabels []string

	hashTacker ObjectHashTracker
}

func (f *AZClientsFactoryImpl) GetAzSubscription(v string) (string, error) {
	if len(v) > 0 {
		return v, nil
	} else if len(f.DefaultAzSubscriptionId) > 0 {
		return f.DefaultAzSubscriptionId, nil
	} else {
		return "", errors.New("input does not supply Azure subscription id, ano no default subscription Id is configured on the provider level")
	}
}

func (f *AZClientsFactoryImpl) AzKeyVaultRSADecrypt(ctx context.Context, input []byte, coord core.WrappingKeyCoordinate) ([]byte, error) {
	client, err := f.GetKeysClient(coord.VaultName)
	if err != nil {
		return nil, err
	}

	options := azkeys.KeyOperationParameters{
		Algorithm: &coord.AzEncryptionAlg,
		Value:     input,
	}

	decrResp, decrErr := client.Decrypt(ctx, coord.KeyName, coord.KeyVersion, options, nil)
	if decrErr != nil {
		tflog.Trace(ctx, fmt.Sprintf("Decryption error: %s", decrErr.Error()))

		return nil, decrErr
	}
	return decrResp.Result, nil
}

func (f *AZClientsFactoryImpl) GetDecrypterFor(ctx context.Context, coord core.WrappingKeyCoordinate) core.RSADecrypter {
	return func(input []byte) ([]byte, error) {
		return f.AzKeyVaultRSADecrypt(ctx, input, coord)
	}
}

func (f *AZClientsFactoryImpl) GetMergedWrappingKeyCoordinate(ctx context.Context, param *core.WrappingKeyCoordinateModel, diag *diag.Diagnostics) core.WrappingKeyCoordinate {

	if f.DisallowResourceSpecifiedWrappingKey {
		pc := param.AsCoordinate()
		if !pc.IsEmpty() {
			diag.AddError("Inadmissible configuration", "Provider configuration explicitly prohibits the use of resource-level wrapping keys")
			return pc
		}
	}

	base := core.WrappingKeyCoordinate{
		VaultName:  core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.VaultName }, param, f.DefaultWrappingKey),
		KeyName:    core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.KeyName }, param, f.DefaultWrappingKey),
		KeyVersion: core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.KeyVersion }, param, f.DefaultWrappingKey),
		Algorithm:  core.GetFirstString(func(m *core.WrappingKeyCoordinateModel) types.String { return m.Algorithm }, param, f.DefaultWrappingKey),
	}

	if base.AddressesKey() {
		// Cache the results of the wrapping keys caches
		cacheKey := fmt.Sprintf("%s/%s/%s", base.VaultName, base.KeyName, base.KeyVersion)

		if f.keysCache != nil {
			if rv, ok := f.keysCache[cacheKey]; ok {
				return rv
			}
		}

		if kClient, err := f.GetKeysClient(base.VaultName); err != nil {
			diag.AddError("cannot obtain key client", err.Error())
		} else {
			base.FillDefaults(ctx, kClient, diag)
			f.CacheWrappingKeyCoordinate(cacheKey, base)
		}
	} else {
		diag.AddError("incomplete coordinate of a wrapping key", "at least vault and key name are required")
	}

	diag.Append(base.Validate()...)

	return base
}

func (cm *AZClientsFactoryImpl) GetDestinationVaultObjectCoordinate(coord core.AzKeyVaultObjectCoordinateModel, objType string) core.AzKeyVaultObjectCoordinate {
	vaultName := cm.DefaultDestinationVault
	if len(coord.VaultName.ValueString()) > 0 {
		vaultName = coord.VaultName.ValueString()
	}

	secretName := coord.Name.ValueString()
	return core.AzKeyVaultObjectCoordinate{
		VaultName: vaultName,
		Name:      secretName,
		Type:      objType,
	}
}

func (f *AZClientsFactoryImpl) IsObjectTrackingEnabled() bool {
	return f.hashTacker != nil
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

// EnsureCanPlaceLabelledObjectAt verifies whether specific constraints for provider and placement are admissible
// to place the object at the intended location.
func (f *AZClientsFactoryImpl) EnsureCanPlaceLabelledObjectAt(_ context.Context, providerConstraints []core.ProviderConstraint, placementConstraints []core.PlacementConstraint, tfResourceType string, targetCoord core.LabelledObject, diagnostics *diag.Diagnostics) {
	if len(providerConstraints) > 0 {
		if !core.AnyIsInWithComparator(
			f.ProviderLabels,
			providerConstraints, func(a string, b core.ProviderConstraint) bool { return a == string(b) }) {
			diagnostics.AddError("Mismatched placement", fmt.Sprintf("The constraints embedded into the ciphertext disallow placement of this %s by this provider. More information is not given for security reasons. Re-encrypt the ciphertext with correct provider constraints.", tfResourceType))
		}
	}

	if len(placementConstraints) > 0 {
		if targetCoord == nil {
			diagnostics.AddError("Nil target object", "The ciphertext embeds requirements as to the target objects that can be created using the contained information, however nil target address is calculated. Either the placement constraint is not necessary, or it's a provider bug that needs to be reported to the maintainer.")
		} else {
			if !core.ContainsWithComparator(
				placementConstraints,
				targetCoord.GetLabel(),
				func(a core.PlacementConstraint, b string) bool { return string(a) == b }) {
				diagnostics.AddError("Mismatched placement", fmt.Sprintf("The constraints embedded into the ciphertext disallow placement of this %s into the specified destination. More information is not given for security reasons. Re-encrypt the ciphertext with correct placement constraints.", tfResourceType))
			}
		}
	}
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

type AzStorageAccountTableTrackerConfigModel struct {
	AccountName   types.String `tfsdk:"account_name"`
	TableName     types.String `tfsdk:"table_name"`
	PartitionName types.String `tfsdk:"partition_name"`
}

type AZConnectorProviderImplModel struct {
	TenantID                     types.String                     `tfsdk:"tenant_id"`
	SubscriptionID               types.String                     `tfsdk:"subscription_id"`
	ClientID                     types.String                     `tfsdk:"client_id"`
	ClientSecret                 types.String                     `tfsdk:"client_secret"`
	DefaultWrappingKeyCoordinate *core.WrappingKeyCoordinateModel `tfsdk:"default_wrapping_key"`

	DisallowResourceSpecifiedWrappingKey types.Bool                               `tfsdk:"disallow_resource_specified_wrapping_key"`
	DefaultDestinationVaultName          types.String                             `tfsdk:"default_destination_vault_name"`
	Labels                               types.Set                                `tfsdk:"labels"`
	FileHashTrackerConfig                *FileHashTrackerConfigModel              `tfsdk:"file_hash_tracker"`
	StorageAccountTracker                *AzStorageAccountTableTrackerConfigModel `tfsdk:"storage_account_tracker"`
}

func (pm *AZConnectorProviderImplModel) GetProviderLabels(ctx context.Context) []string {
	rv := make([]string, len(pm.Labels.Elements()))
	pm.Labels.ElementsAs(ctx, &rv, false)
	return rv
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

func (p *AZConnectorProviderImpl) Metadata(_ context.Context, _ tfprovider.MetadataRequest, resp *tfprovider.MetadataResponse) {
	resp.TypeName = "az-confidential"
	resp.Version = p.version
}

//go:embed provider_description.md
var providerDescription string

func (p *AZConnectorProviderImpl) ConfigValidators(_ context.Context) []tfprovider.ConfigValidator {
	return []tfprovider.ConfigValidator{
		providervalidator.Conflicting(
			path.MatchRoot("file_hash_tracker"),
			path.MatchRoot("storage_account_tracker"),
		),
	}
}

func (p *AZConnectorProviderImpl) Schema(_ context.Context, _ tfprovider.SchemaRequest, resp *tfprovider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Provider importing sensitive secrets, keys, and certificates from Terraform code into Azure KeyVault without exposing plain-text secrets in the state",
		MarkdownDescription: providerDescription,
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
			"labels": schema.SetAttribute{
				MarkdownDescription: "Labels associated with this provider. These labels are used to ensure that the " +
					"the encrypted message can be processed. A practical application of provider labelling is to " +
					"implement environmental or regional separation of various projects. For example, adding " +
					"`labels = [\"test\", \"acceptance\"]` may be used to designate infrastructure intended for " +
					"for testing and (user) acceptance that **cannot** contain production objects of any kind.",
				Optional:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					tfsetvalidators.SizeAtLeast(1),
					// Require at least one element in the labels.
				},
			},
			"file_hash_tracker": schema.SingleNestedAttribute{
				MarkdownDescription: "Configures local file being used to track created objects",
				Description:         "Configures local file being used to track created objects",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"file_name": schema.StringAttribute{
						MarkdownDescription: "File on a local machine where to track created objects",
						Description:         "File on a local machine where to track created objects",
						Required:            true,
					},
				},
			},
			"storage_account_tracker": schema.SingleNestedAttribute{
				MarkdownDescription: "Configures Azure Storage Account table to be used to track objects created",
				Description:         "Configures Azure Storage Account table to be used to track objects created",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"account_name": schema.StringAttribute{
						MarkdownDescription: "Storage account name to use",
						Description:         "Storage account name to use",
						Required:            true,
					},
					"table_name": schema.StringAttribute{
						MarkdownDescription: "Table name to use",
						Description:         "Table name to use",
						Required:            true,
					},
					"partition_name": schema.StringAttribute{
						MarkdownDescription: "Partition name to use",
						Description:         "Partition name to use",
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
			"disallow_resource_specified_wrapping_key": schema.BoolAttribute{
				Optional:            true,
				Description:         "Disallow individual resources to specify resource-level unwrapping keys",
				MarkdownDescription: "Disallow individual resources to specify resource-level unwrapping keys",
			},
		},
	}
}

func (p *AZConnectorProviderImpl) DataSources(ctx context.Context) []func() datasource.DataSource {
	tflog.Debug(ctx, "AzConfidential: initializing data sources")
	return []func() datasource.DataSource{
		general.NewConfidentialPasswordDataSource,
	}
}

func (p *AZConnectorProviderImpl) Resources(ctx context.Context) []func() resource.Resource {
	tflog.Debug(ctx, "AzConfidential: initializing resources")
	return []func() resource.Resource{
		keyvault.NewSecretResource,
		keyvault.NewKeyResource,
		keyvault.NewCertificateResource,
		apim.NewNamedValueResource,
		apim.NewSubscriptionResource,
	}
}

func (p *AZConnectorProviderImpl) ConfigureHashTracker(ctx context.Context, data AZConnectorProviderImplModel, cred azcore.TokenCredential) (ObjectHashTracker, error) {
	if data.StorageAccountTracker != nil {
		return NewAzStorageAccountTracker(
			cred,
			data.StorageAccountTracker.AccountName.ValueString(),
			data.StorageAccountTracker.TableName.ValueString(),
			data.StorageAccountTracker.PartitionName.ValueString(),
		)
	}
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

	hashTracker, hashTrackerInitErr := p.ConfigureHashTracker(ctx, data, cred)
	if hashTrackerInitErr != nil {
		resp.Diagnostics.AddError("Failed to initialize hash tracker", hashTrackerInitErr.Error())
		return
	}

	tflog.Info(ctx, "AzConfidential provider was able to obtain access token to Azure API")

	disallowResourceLevelWrappingKey := false

	if !data.DisallowResourceSpecifiedWrappingKey.IsNull() {
		disallowResourceLevelWrappingKey = data.DisallowResourceSpecifiedWrappingKey.ValueBool()
	}

	factory := &AZClientsFactoryImpl{
		CachedAzClientsSupplier: CachedAzClientsSupplier{
			Credential: cred,
		},

		DefaultWrappingKey:                   data.DefaultWrappingKeyCoordinate,
		DisallowResourceSpecifiedWrappingKey: disallowResourceLevelWrappingKey,
		DefaultAzSubscriptionId:              data.SubscriptionID.ValueString(),

		DefaultDestinationVault: data.DefaultDestinationVaultName.ValueString(),
		ProviderLabels:          data.GetProviderLabels(ctx),
		hashTacker:              hashTracker,
	}

	resp.DataSourceData = factory
	resp.ResourceData = factory

	tflog.Info(ctx, "AzConfidential provider has been configured")

	if factory.hashTacker == nil {
		resp.Diagnostics.AddWarning("Insecure provider configuration", "The provider is not keeping a track of created confidential objects. This setting is discouraged to be used in production setting")
	}
}

func (p *AZConnectorProviderImpl) Functions(_ context.Context) []func() function.Function {
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
