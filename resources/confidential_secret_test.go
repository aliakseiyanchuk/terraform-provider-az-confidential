package resources

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_CSM_ContentTypeAsPtr(t *testing.T) {
	mdl := ConfidentialSecretModel{}

	assert.Nil(t, mdl.ContentTypeAsPtr())

	mdl.ContentType = types.StringValue("application/json")
	assert.NotNil(t, mdl.ContentTypeAsPtr())
	assert.Equal(t, "application/json", *mdl.ContentTypeAsPtr())
}

func Test_CSM_GetDestinationSecretCoordinate(t *testing.T) {
	mdl := ConfidentialSecretModel{
		DestinationSecret: core.AzKeyVaultObjectCoordinateModel{
			Name: types.StringValue("unit-test-secret"),
		},
	}

	rv := mdl.GetDestinationSecretCoordinate("fallback-vault")
	assert.Equal(t, "secret", rv.Type)
	assert.Equal(t, "fallback-vault", rv.VaultName)
	assert.Equal(t, "unit-test-secret", rv.Name)

	mdl.DestinationSecret.VaultName = types.StringValue("specific-vault")
	rv = mdl.GetDestinationSecretCoordinate("fallback-vault")
	assert.Equal(t, "secret", rv.Type)
	assert.Equal(t, "specific-vault", rv.VaultName)
	assert.Equal(t, "unit-test-secret", rv.Name)
}

func Test_CSM_Accept(t *testing.T) {
	mdl := ConfidentialSecretModel{}

	secret := azsecrets.Secret{
		Attributes: &azsecrets.SecretAttributes{
			Enabled:   to.Ptr(true),
			Expires:   to.Ptr(time.Now()),
			NotBefore: to.Ptr(time.Now()),
			Created:   to.Ptr(time.Now()),
		},
		ID: to.Ptr(azsecrets.ID("https://myvaultname.vault.azure.net/secrets/secret1053998307/b86c2e6ad9054f4abf69cc185b99aa60")),
		Tags: map[string]*string{
			"a": to.Ptr("b"),
		},
		ContentType: to.Ptr("application/json"),
		Managed:     to.Ptr(false),
	}

	mdl.Accept(secret)

	assert.Equal(t, string(*secret.ID), mdl.Id.ValueString())
	assert.Equal(t, "b86c2e6ad9054f4abf69cc185b99aa60", mdl.SecretVersion.ValueString())
	assert.Equal(t, "application/json", mdl.ContentType.ValueString())
	assert.True(t, mdl.Enabled.ValueBool())
	assert.False(t, mdl.NotAfter.IsNull())
	assert.False(t, mdl.NotBefore.IsNull())

	receivedTags := mdl.TagsAsStr()
	assert.Equal(t, "b", receivedTags["a"])
	assert.Equal(t, 1, len(receivedTags))
}

func Test_CAzVSR_Metadata(t *testing.T) {
	r := NewConfidentialAzVaultSecretResource()
	req := resource.MetadataRequest{
		ProviderTypeName: "az-confidential",
	}
	resp := resource.MetadataResponse{}

	r.Metadata(nil, req, &resp)
	assert.Equal(t, "az-confidential_secret", resp.TypeName)
}

func Test_CAzVSR_Schema(t *testing.T) {
	r := NewConfidentialAzVaultSecretResource()
	req := resource.SchemaRequest{}
	resp := resource.SchemaResponse{}

	r.Schema(nil, req, &resp)
	assert.NotNil(t, resp.Schema)
	assert.False(t, resp.Diagnostics.HasError())
}

func Test_CAzVSR_DoUpdate_IfResourceIdIsMalformed(t *testing.T) {
	rv := AzKeyVaultSecretResourceSpecializer{}
	data := ConfidentialSecretModel{}
	data.Id = types.StringValue("MalformedString")

	_, dg := rv.DoUpdate(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Resource identifier does not conform to the expected format", dg[0].Summary())
}

func Test_CAzVSR_DoUpdate_IfClientCannotConnect(t *testing.T) {

	data := ConfidentialSecretModel{}
	data.Id = types.StringValue("https://cfg-vault.vaults.unittests/secrets/secretName/secretVesion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetdestinationVaultObjectCoordinate("cfg-vault", "secrets", "secretName")
	factory.GivenGetSecretClientWillReturnError("cfg-vault", "unit-test-error")

	rv := AzKeyVaultSecretResourceSpecializer{}
	rv.factory = &factory

	_, dg := rv.DoUpdate(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire secret client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVSR_DoUpdate_IfReturnedClientIsNil(t *testing.T) {

	data := ConfidentialSecretModel{}
	data.Id = types.StringValue("https://cfg-vault.vaults.unittests/secrets/secretName/secretVesion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetdestinationVaultObjectCoordinate("cfg-vault", "secrets", "secretName")
	factory.GivenGetSecretClientWillReturnNilClient("cfg-vault")

	rv := AzKeyVaultSecretResourceSpecializer{}
	rv.factory = &factory

	_, dg := rv.DoUpdate(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire secret client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVSR_DoUpdate_IfUpdatingPropertiesWillFail(t *testing.T) {

	data := ConfidentialSecretModel{}
	data.Id = types.StringValue("https://cfg-vault.vaults.unittests/secrets/secretName/secretVersion")

	clMock := SecretClientMock{}
	clMock.GivenUpdateSecretPropertiesWillReturnError("secretName", "secretVersion", "unit-test-error")

	factory := AZClientsFactoryMock{}
	factory.GivenGetdestinationVaultObjectCoordinate("cfg-vault", "secrets", "secretName")
	factory.GivenGetSecretClientWillReturn("cfg-vault", &clMock)

	rv := AzKeyVaultSecretResourceSpecializer{}
	rv.factory = &factory

	_, dg := rv.DoUpdate(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Error updating secret properties", dg[0].Summary())

	factory.AssertExpectations(t)
	clMock.AssertExpectations(t)
}

func Test_CAzVSR_DoUpdate_Succeeds(t *testing.T) {

	data := ConfidentialSecretModel{}
	data.Id = types.StringValue("https://cfg-vault.vaults.unittests/secrets/secretName/secretVersion")

	clMock := SecretClientMock{}
	clMock.GivenUpdateSecretPropertiesWillSucceed("secretName", "secretVersion", "unit-test-secret")

	factory := AZClientsFactoryMock{}
	factory.GivenGetdestinationVaultObjectCoordinate("cfg-vault", "secrets", "secretName")
	factory.GivenGetSecretClientWillReturn("cfg-vault", &clMock)

	rv := AzKeyVaultSecretResourceSpecializer{}
	rv.factory = &factory

	_, dg := rv.DoUpdate(context.Background(), &data)
	assert.False(t, dg.HasError())

	factory.AssertExpectations(t)
	clMock.AssertExpectations(t)
}

func Test_CAzVSR_DoUpdate_ImplicitMove(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetdestinationVaultObjectCoordinate("movedVault", "secrets", "secretName")

	r := AzKeyVaultSecretResourceSpecializer{}
	r.factory = &factory

	planData := ConfidentialSecretModel{
		DestinationSecret: core.AzKeyVaultObjectCoordinateModel{
			Name: types.StringValue("secretName"),
		},
	}
	planData.Id = types.StringValue("https://cfg-vault.vaults.unittests/secrets/secretName/secretVesion")

	_, dg := r.DoUpdate(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Implicit object move", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVSR_DoRead_WillExitIfSecretVersionIsNotKnown(t *testing.T) {
	c := AzKeyVaultSecretResourceSpecializer{}
	mdl := ConfidentialSecretModel{}
	mdl.Id = types.StringUnknown()

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.Equal(t, ResourceNotYetCreated, resourceExistsCheck)
	assert.False(t, dg.HasError())
}

func Test_CAzVSR_DoRead_WillExitErrIfIdIsMalformed(t *testing.T) {
	c := AzKeyVaultSecretResourceSpecializer{}
	mdl := ConfidentialSecretModel{
		SecretVersion: types.StringValue("abc"),
	}
	mdl.Id = types.StringValue("https://malformed-id/")

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, ResourceCheckError, resourceExistsCheck)
}

func Test_CAzVSR_DoRead_WillReportErrorIfKVClientCannotBeGained(t *testing.T) {
	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturnError("unit-test-vault", "unit-test-error")

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	mdl := GivenTypicalConfidentialSecretModel()

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire secret client", dg[0].Summary())
	assert.Equal(t, "Cannot acquire secret client to vault unit-test-vault: unit-test-error", dg[0].Detail())
	assert.Equal(t, ResourceCheckError, resourceExistsCheck)
}

func Test_CAzVSR_DoRead_WillReportErrorIfKVClientWillBeNull(t *testing.T) {
	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturnNilClient("unit-test-vault")

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	mdl := GivenTypicalConfidentialSecretModel()

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire secret client", dg[0].Summary())
	assert.Equal(t, "Secrets client returned is nil", dg[0].Detail())
	assert.Equal(t, ResourceCheckError, resourceExistsCheck)
}

func Test_CAzVSR_DoRead_WillAddWarningOnDeletedObjectIfTrackingIsEnabled(t *testing.T) {
	secretClient := SecretClientMock{}
	secretClient.GivenGetSecretWillReturnObjectNotFound("secretName", "secretVersion")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &secretClient)
	factoryMock.GivenIsObjectTrackingEnabled(true)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	mdl := GivenTypicalConfidentialSecretModel()

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.Equal(t, "Secret removed from key vault", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())
	assert.Equal(t, ResourceNotFound, resourceExistsCheck)

	secretClient.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoRead_WillNotAddWarningOnDeletedObjectIfTrackingIsDisabled(t *testing.T) {
	secretClient := SecretClientMock{}
	secretClient.GivenGetSecretWillReturnObjectNotFound("secretName", "secretVersion")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &secretClient)
	factoryMock.GivenIsObjectTrackingEnabled(false)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	mdl := GivenTypicalConfidentialSecretModel()

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.Equal(t, 0, len(dg))
	assert.Equal(t, ResourceNotFound, resourceExistsCheck)

	secretClient.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoRead_IfReadingSecretReturnsAnError(t *testing.T) {
	secretClient := SecretClientMock{}
	secretClient.GivenGetSecretWillReturnError("secretName", "secretVersion", "unit-test-error")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &secretClient)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	mdl := GivenTypicalConfidentialSecretModel()

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot read secret", dg[0].Summary())
	assert.Equal(t, ResourceCheckError, resourceExistsCheck)

	secretClient.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoRead(t *testing.T) {
	secretClient := SecretClientMock{}
	secretClient.GivenGetSecret("secretName", "secretVersion", "secretValue")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &secretClient)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	mdl := GivenTypicalConfidentialSecretModel()

	_, resourceExistsCheck, dg := c.DoRead(context.Background(), &mdl)
	assert.False(t, dg.HasError())
	assert.Equal(t, ResourceExists, resourceExistsCheck)

	secretClient.AssertExpectations(t)
	factoryMock.AssertExpectations(t)
}

func GivenTypicalConfidentialSecretModel() ConfidentialSecretModel {
	mdl := ConfidentialSecretModel{
		ContentType:   types.StringValue("application/json"),
		SecretVersion: types.StringValue("secretVersion"),
	}

	mdl.Id = types.StringValue("https://unit-test-vault/secrets/secretName/secretVersion")
	return mdl
}

func Test_CAzVSR_DoDelete_IfIdIsUnknown(t *testing.T) {
	mdl := ConfidentialSecretModel{}
	mdl.Id = types.StringUnknown()

	c := AzKeyVaultSecretResourceSpecializer{}
	dg := c.DoDelete(context.Background(), &mdl)

	assert.Equal(t, 1, len(dg))
	assert.Equal(t, "Incomplete configuration", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())
}

func Test_CAzVSR_DoDelete_IfIdIsMalformed(t *testing.T) {
	mdl := ConfidentialSecretModel{}
	mdl.Id = types.StringValue("this is not an id")

	c := AzKeyVaultSecretResourceSpecializer{}
	dg := c.DoDelete(context.Background(), &mdl)

	assert.True(t, dg.HasError())
	assert.Equal(t, "Error getting secret coordinate", dg[0].Summary())
}

func Test_CAzVSR_DoDelete_IfCannotGetClient(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturnError("unit-test-vault", "unit-test-error")

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	dg := c.DoDelete(context.Background(), &mdl)

	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire secret client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoDelete_IfWillGetNilClient(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturnNilClient("unit-test-vault")

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	dg := c.DoDelete(context.Background(), &mdl)

	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire secret client", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoDelete_IfUpdatePropertiesWillFail(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()

	clientMock := SecretClientMock{}
	clientMock.GivenUpdateSecretPropertiesWillReturnError("secretName", "secretVersion", "unit-test-error")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &clientMock)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	dg := c.DoDelete(context.Background(), &mdl)

	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot disable secret version", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoDelete(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()

	clientMock := SecretClientMock{}
	clientMock.GivenUpdateSecretPropertiesWillSucceed("secretName", "secretVersion", "read-back-secret")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &clientMock)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	dg := c.DoDelete(context.Background(), &mdl)

	assert.False(t, dg.HasError())
	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoCreate_IfClientCannotConnect(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()
	ptData := core.VersionedConfidentialData{}

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetdestinationVaultObjectCoordinate("unit-test-vault", "secrets", "secretName")
	factoryMock.GivenGetSecretClientWillReturnError("unit-test-vault", "unit-test-error")

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	_, dg := c.DoCreate(context.Background(), &mdl, ptData)

	assert.True(t, dg.HasError())
	assert.Equal(t, "Error acquiring secret client", dg[0].Summary())
	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoCreate_IfClientIsNil(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()
	ptData := core.VersionedConfidentialData{}

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetdestinationVaultObjectCoordinate("unit-test-vault", "secrets", "secretName")
	factoryMock.GivenGetSecretClientWillReturnNilClient("unit-test-vault")

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	_, dg := c.DoCreate(context.Background(), &mdl, ptData)

	assert.True(t, dg.HasError())
	assert.Equal(t, "Error acquiring secret client", dg[0].Summary())
	factoryMock.AssertExpectations(t)
}

func Test_CAzVSR_DoCreate_IfSetSecretErrors(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()
	ptData := core.VersionedConfidentialData{}

	clMock := SecretClientMock{}
	clMock.GivenSetSecretWillReturnError("secretName", "unit-test-error")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetdestinationVaultObjectCoordinate("unit-test-vault", "secrets", "secretName")
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &clMock)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	_, dg := c.DoCreate(context.Background(), &mdl, ptData)

	assert.True(t, dg.HasError())
	assert.Equal(t, "Error setting secret", dg[0].Summary())

	factoryMock.AssertExpectations(t)
	clMock.AssertExpectations(t)
}

func Test_CAzVSR_DoCreate(t *testing.T) {
	mdl := GivenTypicalConfidentialSecretModel()
	ptData := core.VersionedConfidentialData{}

	clMock := SecretClientMock{}
	clMock.GivenSetSecret("secretName", "secretVersion")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetdestinationVaultObjectCoordinate("unit-test-vault", "secrets", "secretName")
	factoryMock.GivenGetSecretClientWillReturn("unit-test-vault", &clMock)

	c := AzKeyVaultSecretResourceSpecializer{}
	c.factory = &factoryMock

	_, dg := c.DoCreate(context.Background(), &mdl, ptData)

	assert.False(t, dg.HasError())

	factoryMock.AssertExpectations(t)
	clMock.AssertExpectations(t)
}
