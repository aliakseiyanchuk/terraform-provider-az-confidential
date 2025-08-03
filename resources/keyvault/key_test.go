package keyvault

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func mustDecodeBase64(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err != nil {
		panic(err)
	} else {
		return b
	}
}

func Test_CKMdl_GetKeyOperations(t *testing.T) {
	set, err := core.ConvertToTerraformSet[string](
		func(k string) attr.Value { return types.StringValue(k) },
		types.StringType,
		core.MapSlice(func(i azkeys.KeyOperation) string { return string(i) }, azkeys.PossibleKeyOperationValues())...,
	)
	assert.Nil(t, err)

	mdl := KeyModel{
		KeyOperations: set,
	}

	operations := mdl.GetKeyOperations(context.Background())
	operationsBag := core.MapSlice(func(k *azkeys.KeyOperation) azkeys.KeyOperation { return *k }, operations)

	assert.True(t, core.SameBag(
		func(a, b azkeys.KeyOperation) bool { return a == b },
		operationsBag,
		azkeys.PossibleKeyOperationValues()),
	)
}

func Test_CKMdl_AcceptECKey(t *testing.T) {
	ccm := givenPreviouslyCreatedKeyModel()

	keyID := to.Ptr(ccm.Id.ValueString())
	key := azkeys.JSONWebKey{
		Crv: to.Ptr(azkeys.CurveNameP256),
		KID: (*azkeys.ID)(keyID),
		Kty: to.Ptr(azkeys.KeyTypeEC),
		X:   mustDecodeBase64("AQX6InFKrBSdHa+rr9sMgLOUZYSKyVDNrdJn0BypmyI="),
		Y:   mustDecodeBase64("hDe5IvSt+40KnjAOTlXYCsd16blXtqLVWASQBRjbJEA="),
	}

	keyBundle := azkeys.KeyBundle{
		Key: &key,
		Attributes: &azkeys.KeyAttributes{
			Enabled: to.Ptr(true),
		},
		Tags: map[string]*string{
			"environment": to.Ptr("unit-test"),
		},
	}

	dg := diag.Diagnostics{}
	ccm.Accept(keyBundle, &dg)

	assert.False(t, dg.HasError())
	assert.False(t, ccm.PublicKeyPem.IsNull())
}

func givenPreviouslyCreatedKeyModel() KeyModel {
	keyIdStr := "https://unit-test-fictitious-vault-name.vault.azure.net/keys/importedkeyv1/88ac1c5c71df4c169ab70d3ded5192f4"

	ccm := KeyModel{}
	ccm.Id = types.StringValue(keyIdStr)
	ccm.KeyVersion = types.StringValue("88ac1c5c71df4c169ab70d3ded5192f4")

	return ccm
}

func givenInboundKeyForPreviouslyCreated(mdl *KeyModel, cfg core.Consumer[*azkeys.KeyBundle]) *azkeys.KeyBundle {
	key := azkeys.JSONWebKey{
		KID: (*azkeys.ID)(to.Ptr(mdl.Id.ValueString())),
	}

	keyBundle := azkeys.KeyBundle{
		Key: &key,
		Attributes: &azkeys.KeyAttributes{
			Enabled: to.Ptr(true),
		},
	}
	cfg(&keyBundle)
	return &keyBundle
}

func Test_CKMdl_AcceptRsaKey(t *testing.T) {
	ccm := givenPreviouslyCreatedKeyModel()

	key := azkeys.JSONWebKey{
		KID: (*azkeys.ID)(to.Ptr(ccm.Id.ValueString())),
		E:   mustDecodeBase64("AQAB"),
		Kty: to.Ptr(azkeys.KeyTypeRSA),
		N:   mustDecodeBase64("x6PaXN8G5yqJc06mB+HtzcHEvg5CXE8K2MgIqLjGGoOJJrxvdyj4ahxn434VVEFwlN0IDRvw4nsZwNOmXtQHqNYUHFJTfPVgbywjRPc72/v/81KVaMEDyLBgLKBndcAROYi2HTgp7DtllZGLCOFDMH0SwuAlJ/jM/O4YUksWyQRzVaEXYFoZvU48wKUp691Pp30xgAfaDKmXKXk/gJP+WqmaCEHLU26xxflOn0Jh50plClxfE5VNygeWNX2qfcHoeuV4AVktUhYMXXbaZar7cofVVg/Xb9RIDQtVtFEOBiOKLrDuFKmiJIcQm+SVPxVm32SwSaSJ32Mo68xc0VRZlwWZsU88mgfB0irQGigf1uSgbeyyhP1LqwO9Ko2axz4we86rr87MdV6fXwyLzofDUroQkCpX97h6kRpt2Oo+6a6dVMB0i1o39e0+s/x30DyF/NmYfp6OZeZ9ESexNK+Irs7AON0qsktMvJrZrwtWJc3dpR62/QOdYsn6Gg3Awz5/mVJmUXUeTlSNUwLXvRcg6+0R7h1I9QSsMp2rBrReJic3xzeU48v1Nsx8bThdHhHniJxbQKHLLPTkFPvU1GVQ/4+V/CknT5iV3y+hgcLK+RA013P7ZjYApzpVkMfBcUZbKzKOTb++nXzlJrWwCc2bkHaPtEkvXVnamkL9RoClPnk="),
	}

	keyBundle := azkeys.KeyBundle{
		Key: &key,
		Attributes: &azkeys.KeyAttributes{
			Enabled: to.Ptr(true),
		},
	}

	dg := diag.Diagnostics{}
	ccm.Accept(keyBundle, &dg)

	assert.False(t, dg.HasError())
	assert.False(t, ccm.PublicKeyPem.IsNull())
}

func Test_CKMdl_Accept_NilKeyOps(t *testing.T) {
	dg := diag.Diagnostics{}
	mdl := givenPreviouslyCreatedKeyModel()
	keyBundle := givenInboundKeyForPreviouslyCreated(&mdl, func(k *azkeys.KeyBundle) {
		k.Key.KeyOps = nil
	})

	// Accept should set nil value if operations are unknown
	mdl.KeyOperations = types.SetUnknown(types.StringType)
	mdl.Accept(*keyBundle, &dg)
	assert.True(t, mdl.KeyOperations.IsNull())

	// Accept should set nil value if operations are empty
	mdl = givenPreviouslyCreatedKeyModel()
	mdl.KeyOperations = types.SetNull(types.StringType)
	mdl.Accept(*keyBundle, &dg)

	assert.True(t, mdl.KeyOperations.IsNull())

	// Accept should leave an empty set untouched.
	mdl = givenPreviouslyCreatedKeyModel()
	mdl.KeyOperations = core.CreateEmptyTerraformSet(types.StringType)
	mdl.Accept(*keyBundle, &dg)
	assert.False(t, mdl.KeyOperations.IsNull())
	assert.Equal(t, 0, len(mdl.KeyOperations.Elements()))

	// Accept should leave an empty set untouched.
	mdl = givenPreviouslyCreatedKeyModel()
	mdl.KeyOperations = core.CreateEmptyTerraformSet(types.StringType)

	keyBundleWithEmptyKeyOps := givenInboundKeyForPreviouslyCreated(&mdl, func(k *azkeys.KeyBundle) {
		k.Key.KeyOps = []*azkeys.KeyOperation{}
	})

	mdl.Accept(*keyBundleWithEmptyKeyOps, &dg)
	assert.False(t, mdl.KeyOperations.IsNull())
	assert.Equal(t, 0, len(mdl.KeyOperations.Elements()))
}

func Test_CKMdl_Accept_KeyOps(t *testing.T) {
	dg := diag.Diagnostics{}

	expectedOperations := []azkeys.KeyOperation{
		azkeys.KeyOperationDecrypt,
		azkeys.KeyOperationEncrypt,
	}

	mdl := givenPreviouslyCreatedKeyModel()
	keyBundle := givenInboundKeyForPreviouslyCreated(&mdl, func(k *azkeys.KeyBundle) {
		k.Key.KeyOps = core.MapSlice(to.Ptr, expectedOperations)
	})

	// Accept should set nil value if operations are unknown
	mdl.KeyOperations = types.SetUnknown(types.StringType)
	mdl.Accept(*keyBundle, &dg)
	assert.False(t, dg.HasError())

	acceptedOperations := make([]string, len(mdl.KeyOperations.Elements()))
	mdl.KeyOperations.ElementsAs(context.Background(), &acceptedOperations, false)

	assert.True(t, core.EquivalentBag(
		func(a azkeys.KeyOperation, b string) bool { return string(a) == b },
		expectedOperations,
		acceptedOperations,
	))

}

func Test_CKMdl_Accept_IfKeyNull(t *testing.T) {
	dg := diag.Diagnostics{}

	c := azkeys.KeyBundle{}
	mdl := givenPreviouslyCreatedKeyModel()

	mdl.Accept(c, &dg)
	assert.Equal(t, 1, len(dg))
	assert.Equal(t, "Superfluous key conversion", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())
}

func Test_CKMdl_Accept_IfKeyIdIsNil(t *testing.T) {
	dg := diag.Diagnostics{}

	c := azkeys.KeyBundle{
		Key: &azkeys.JSONWebKey{},
	}
	mdl := givenPreviouslyCreatedKeyModel()

	mdl.Accept(c, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Conversion request for key having nil key identifier", dg[0].Summary())
}

func Test_CKMdl_Accept_IfIdDiffers(t *testing.T) {
	dg := diag.Diagnostics{}

	c := azkeys.KeyBundle{
		Key: &azkeys.JSONWebKey{
			KID: to.Ptr(azkeys.ID("this is a wrong id")),
		},
	}
	mdl := givenPreviouslyCreatedKeyModel()

	mdl.Accept(c, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Conflicting key", dg[0].Summary())
}

func Test_CKMdl_Accept_IfVersionDiffers(t *testing.T) {
	dg := diag.Diagnostics{}
	mdl := givenPreviouslyCreatedKeyModel()
	mdl.KeyVersion = types.StringValue("this is a different version in state")

	c := azkeys.KeyBundle{
		Key: &azkeys.JSONWebKey{
			KID: to.Ptr(azkeys.ID(mdl.Id.ValueString())),
		},
	}

	mdl.Accept(c, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Conflicting key version", dg[0].Summary())
}

func Test_CKMdl_Accept_KeyId(t *testing.T) {
	dg := diag.Diagnostics{}
	mdl := KeyModel{}
	mdl.Id = types.StringUnknown()
	mdl.KeyVersion = types.StringUnknown()

	c := azkeys.KeyBundle{
		Key: &azkeys.JSONWebKey{
			KID: to.Ptr(azkeys.ID("https://unit-test-fictitious-vault-name.vault.azure.net/keys/importedkeyv1/88ac1c5c71df4c169ab70d3ded5192f4")),
		},
	}

	mdl.Accept(c, &dg)
	assert.False(t, dg.HasError())
	assert.False(t, mdl.Id.IsNull())
	assert.False(t, mdl.KeyVersion.IsNull())
	assert.Equal(t, "https://unit-test-fictitious-vault-name.vault.azure.net/keys/importedkeyv1/88ac1c5c71df4c169ab70d3ded5192f4", mdl.Id.ValueString())
	assert.Equal(t, "88ac1c5c71df4c169ab70d3ded5192f4", mdl.KeyVersion.ValueString())
}

func Test_CKMdl_ConvertToUpdateKeyParamFallsBackToDefaultVaultName(t *testing.T) {
	mdl := KeyModel{
		DestinationKey: core.AzKeyVaultObjectCoordinateModel{
			Name: types.StringValue("keyName"),
		},
	}

	coord := mdl.GetDestinationKeyCoordinate("defaultKeyVaultName")
	assert.Equal(t, "keyName", coord.Name)
	assert.Equal(t, "defaultKeyVaultName", coord.VaultName)
	assert.Equal(t, "keys", coord.Type)
}

func Test_CKMdl_ConvertToUpdateKeyParamUsesExplicit(t *testing.T) {
	mdl := KeyModel{
		DestinationKey: core.AzKeyVaultObjectCoordinateModel{
			VaultName: types.StringValue("vaultName"),
			Name:      types.StringValue("keyName"),
		},
	}

	coord := mdl.GetDestinationKeyCoordinate("defaultKeyVaultName")
	assert.Equal(t, "keyName", coord.Name)
	assert.Equal(t, "vaultName", coord.VaultName)
	assert.Equal(t, "keys", coord.Type)
}

func Test_CAzVKR_DoRead_IfNotInitialized(t *testing.T) {
	mdl := KeyModel{}
	mdl.Id = types.StringUnknown()

	ks := AzKeyVaultKeyResourceSpecializer{}
	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceNotYetCreated, state)
	assert.False(t, dg.HasError())
}

func Test_CAzVKR_DoRead_IfIdIsMalformed(t *testing.T) {
	mdl := KeyModel{}
	mdl.Id = types.StringValue("this is not a valid id")

	ks := AzKeyVaultKeyResourceSpecializer{}
	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "cannot establish reference to the created key version", dg[0].Summary())
}

func Test_CAzVKR_DoRead_IfKeysClientCannotConnect(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturnError("unit-test-vault", "unit-test-error")
	mdl := givenTypicalKeyModel()

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire keys client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVKR_DoRead_IfNilKeysClientReturned(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturnNilClient("unit-test-vault")
	mdl := givenTypicalKeyModel()

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire keys client", dg[0].Summary())
	assert.Equal(t, "Keys client returned is nil", dg[0].Detail())

	factory.AssertExpectations(t)
}
func Test_CAzVKR_DoRead_WhenKeyNotFoundAndTrackingEnabled(t *testing.T) {

	keysClient := KeysClientMock{}
	keysClient.GivenGetKeyReturnsObjectNotFound("keyName", "keyVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenIsObjectTrackingEnabled(true)
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &keysClient)

	mdl := givenTypicalKeyModel()

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceNotFound, state)
	assert.False(t, dg.HasError())
	assert.Equal(t, "Warning", dg[0].Severity().String())
	assert.Equal(t, "Key removed from key vault", dg[0].Summary())

	factory.AssertExpectations(t)
	keysClient.AssertExpectations(t)
}

func Test_CAzVKR_DoRead_WhenKeyNotFoundAndTrackingDisabled(t *testing.T) {

	keysClient := KeysClientMock{}
	keysClient.GivenGetKeyReturnsObjectNotFound("keyName", "keyVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenIsObjectTrackingEnabled(false)
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &keysClient)

	mdl := givenTypicalKeyModel()

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceNotFound, state)
	assert.Equal(t, 0, len(dg))

	factory.AssertExpectations(t)
	keysClient.AssertExpectations(t)
}

func Test_CAzVKR_DoRead_WhenReadingKeyReturnsAnError(t *testing.T) {

	keysClient := KeysClientMock{}
	keysClient.GivenGetKeyReturnsError("keyName", "keyVersion", "unit-test-error-message")

	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &keysClient)

	mdl := givenTypicalKeyModel()

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceCheckError, state)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot read key", dg[0].Summary())

	factory.AssertExpectations(t)
	keysClient.AssertExpectations(t)
}

func Test_CAzVKR_DoRead(t *testing.T) {

	keysClient := KeysClientMock{}
	keysClient.GivenGetKey("keyName", "keyVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &keysClient)

	mdl := givenTypicalKeyModel()

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, state, dg := ks.DoRead(context.Background(), &mdl)
	assert.Equal(t, resources.ResourceExists, state)
	assert.False(t, dg.HasError())

	factory.AssertExpectations(t)
	keysClient.AssertExpectations(t)
}

func givenTypicalKeyModel() KeyModel {
	mdl := KeyModel{}
	mdl.Id = types.StringValue("https://unit-test-vault/keys/keyName/keyVersion")
	return mdl
}

func givenLoadedJWKKey() jwk.Key {
	//rsaPrivateKey, _ := core.GenerateEphemeralKeyPair()
	jwkKey, _ := jwk.Import(testkeymaterial.EphemeralRsaKeyText)
	return jwkKey
}

func givenVersionedBinaryConfidentialDataFromString(s string) core.ConfidentialBinaryData {
	md := core.SecondaryProtectionParameters{}

	helper := core.NewVersionedBinaryConfidentialDataHelper(KeyObjectType)
	return helper.CreateConfidentialBinaryData([]byte(s), md).Data
}

//func Test_CAzVKR_DoCreate_IfDataIsNotGZipCompressed(t *testing.T) {
//	mdl := givenTypicalKeyModel()
//	confidentialData := givenVersionedBinaryConfidentialDataFromString("this is not a GZip data")
//	ks := AzKeyVaultKeyResourceSpecializer{}
//
//	_, dg := ks.DoCreate(context.Background(), &mdl, confidentialData)
//	assert.True(t, dg.HasError())
//	assert.Equal(t, "Binary data is not GZip-compressed", dg[0].Summary())
//}

func Test_CAzVKR_DoCreate_IfKeyClientCannotConnect(t *testing.T) {
	mdl := givenTypicalKeyModel()
	confidentialData := givenLoadedJWKKey()

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factoryMock.GivenGetKeysClientWillReturnError("unit-test-vault", "unit-test-error-message")

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confidentialData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Az key vault keys client cannot be retrieved", dg[0].Summary())

	factoryMock.AssertExpectations(t)
}

func Test_CAzVKR_DoCreate_IfKeyClientWillBeNil(t *testing.T) {
	mdl := givenTypicalKeyModel()
	confidentialData := givenLoadedJWKKey()

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factoryMock.GivenGetKeysClientWillReturnNilClient("unit-test-vault")

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confidentialData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Az key vault keys client cannot be retrieved", dg[0].Summary())
	assert.Equal(t, "Nil client returned while no error was raised. This is a provider bug. Please report this", dg[0].Detail())

	factoryMock.AssertExpectations(t)
}

func Test_CAzVKR_DoCreate_IfImportFails(t *testing.T) {
	mdl := givenTypicalKeyModel()
	// JWK data needs binary elements initialized
	confidentialData := givenLoadedJWKKey()

	clientMock := KeysClientMock{}
	clientMock.GivenImportKeyReturnsError("keyName", "unit-test-error-message")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factoryMock.GivenGetKeysClientWillReturn("unit-test-vault", &clientMock)

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confidentialData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Error import key", dg[0].Summary())

	factoryMock.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVKR_DoCreate(t *testing.T) {
	mdl := givenTypicalKeyModel()
	// JWK data needs binary elements initialized
	confidentialData := givenLoadedJWKKey()

	clientMock := KeysClientMock{}
	clientMock.GivenImportKey("keyName")

	factoryMock := AZClientsFactoryMock{}
	factoryMock.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factoryMock.GivenGetKeysClientWillReturn("unit-test-vault", &clientMock)

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factoryMock,
	}

	_, dg := ks.DoCreate(context.Background(), &mdl, confidentialData)
	assert.False(t, dg.HasError())

	factoryMock.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVKR_DoUpdate_IfResourceIdIsNotValid(t *testing.T) {
	mdl := KeyModel{}
	mdl.Id = types.StringValue("this is not a valid identifier")

	r := AzKeyVaultKeyResourceSpecializer{}
	_, dg := r.DoUpdate(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Error getting destination key coordinate", dg[0].Summary())
}

func Test_CAzVKR_DoUpdate_ImplicitMove(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("movedVault", "keys", "keyName")

	r := AzKeyVaultKeyResourceSpecializer{}
	r.factory = &factory

	planData := KeyModel{
		DestinationKey: core.AzKeyVaultObjectCoordinateModel{
			Name: types.StringValue("keyName"),
		},
	}
	planData.Id = types.StringValue("https://cfg-vault.vaults.unittests/keys/keyName/keyVesion")

	_, rv := r.DoUpdate(context.Background(), &planData)
	assert.True(t, rv.HasError())
	assert.Equal(t, "Implicit object move", rv[0].Summary())
}

func Test_CAzVKR_DoUpdate_IfKeyClientCannotConnect(t *testing.T) {
	mdl := givenTypicalKeyModel()

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factory.GivenGetKeysClientWillReturnError("unit-test-vault", "unit-test-error-message")

	r := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, dg := r.DoUpdate(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire keys client", dg[0].Summary())

	factory.AssertExpectations(t)
}
func Test_CAzVKR_DoUpdate_IfKeyClientIsNil(t *testing.T) {
	mdl := givenTypicalKeyModel()

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factory.GivenGetKeysClientWillReturnNilClient("unit-test-vault")

	r := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, dg := r.DoUpdate(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire keys client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVKR_DoUpdate_IfUpdateFails(t *testing.T) {
	mdl := givenTypicalKeyModel()

	clientMock := KeysClientMock{}
	clientMock.GivenUpdateKeyReturnsError("keyName", "keyVersion", "unit-test-error-mess")

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &clientMock)

	r := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, dg := r.DoUpdate(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Error updating key properties", dg[0].Summary())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVKR_DoUpdate(t *testing.T) {
	mdl := givenTypicalKeyModel()

	clientMock := KeysClientMock{}
	clientMock.GivenUpdateKey("keyName", "keyVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "keys", "keyName")
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &clientMock)

	r := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}

	_, dg := r.DoUpdate(context.Background(), &mdl)
	assert.False(t, dg.HasError())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVKR_DoDelete_IfIdIsNotKnown(t *testing.T) {
	mdl := KeyModel{}
	mdl.Id = types.StringUnknown()

	ks := AzKeyVaultKeyResourceSpecializer{}
	dg := ks.DoDelete(context.Background(), &mdl)
	assert.False(t, dg.HasError())
	assert.Equal(t, "Superfluous delete call", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())
}

func Test_CAzVKR_DoDelete_IfIdIsMalformed(t *testing.T) {
	mdl := KeyModel{}
	mdl.Id = types.StringValue("this is not a valid identifier")

	ks := AzKeyVaultKeyResourceSpecializer{}
	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Error getting destination key coordinate", dg[0].Summary())
}

func Test_CAzVKR_DoDelete_IfClientCannotConnect(t *testing.T) {
	mdl := givenTypicalKeyModel()

	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturnError("unit-test-vault", "unit-test-error-mess")

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}
	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire keys client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVKR_DoDelete_IfClientIsNil(t *testing.T) {
	mdl := givenTypicalKeyModel()

	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturnNilClient("unit-test-vault")

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}
	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire keys client", dg[0].Summary())
	assert.Equal(t, "Keys client returned is nil. This is a provider error. Please report this issue", dg[0].Detail())

	factory.AssertExpectations(t)
}

func Test_CAzVKR_DoDelete_IfUpdateFails(t *testing.T) {
	mdl := givenTypicalKeyModel()

	clientMock := KeysClientMock{}
	clientMock.GivenUpdateKeyReturnsError("keyName", "keyVersion", "unit-test-error")

	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &clientMock)

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}
	dg := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot disable key version", dg[0].Summary())
	assert.Equal(t, "Request to disable key's keyName version keyVersion in vault unit-test-vault failed: unit-test-error", dg[0].Detail())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVKR_DoDelete(t *testing.T) {
	mdl := givenTypicalKeyModel()

	clientMock := KeysClientMock{}
	clientMock.GivenUpdateKey("keyName", "keyVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetKeysClientWillReturn("unit-test-vault", &clientMock)

	ks := AzKeyVaultKeyResourceSpecializer{
		factory: &factory,
	}
	dg := ks.DoDelete(context.Background(), &mdl)
	assert.False(t, dg.HasError())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func TestNewConfidentialAzVaultKeyResource(t *testing.T) {
	// Testing that bootstrapping the resource would complete.
	_ = NewKeyResource()
}

func TestNewKeyEncryptorFunctionWillReturn(t *testing.T) {
	f := NewKeyEncryptorFunction()
	assert.NotNil(t, f)
}

// ----------------------------------
// Testing various methods of acquiring a JWT key.

func Test_CAzVKR_AcquireKey_PemNoPassword(t *testing.T) {
	key, err := AcquireJWT(testkeymaterial.EphemeralRsaKeyText, "")
	assert.NoError(t, err)
	_, ok := key.(jwk.RSAPrivateKey)
	assert.True(t, ok)
}

func Test_CAzVKR_AcquireKey_PemWrongPassword(t *testing.T) {
	_, err := AcquireJWT(testkeymaterial.EphemeralEncryptedRsaKeyText, "")
	assert.Error(t, err)

}

func Test_CAzVKR_AcquireKey_PemEncryptedCorrectPassword(t *testing.T) {
	key, err := AcquireJWT(testkeymaterial.EphemeralEncryptedRsaKeyText, "s1cr3t")
	assert.NoError(t, err)
	_, ok := key.(jwk.RSAPrivateKey)
	assert.True(t, ok)
}

func Test_CAzVKR_AcquireKey_PemEncryptedWrongPassword(t *testing.T) {
	_, err := AcquireJWT(testkeymaterial.EphemeralEncryptedRsaKeyDERForm, "")
	assert.Error(t, err)
}

func Test_CAzVKR_AcquireKey_DEREncryptedCorrectPassword(t *testing.T) {
	key, err := AcquireJWT(testkeymaterial.EphemeralEncryptedRsaKeyDERForm, "s1cr3t")
	assert.NoError(t, err)
	_, ok := key.(jwk.RSAPrivateKey)
	assert.True(t, ok)
}

func Test_CreateKeyEncryptedMessage_NonLocking(t *testing.T) {
	reqMd := core.SecondaryProtectionParameters{
		CreateLimit:         100,
		Expiry:              200,
		ProviderConstraints: []core.ProviderConstraint{"acceptance"},
		NumUses:             300,
	}

	privKey, privKeyErr := AcquireJWT(testkeymaterial.EphemeralRsaKeyText, "")
	assert.NoError(t, privKeyErr)

	rsaKey, err := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.NoError(t, err)

	_, md, err := CreateKeyEncryptedMessage(privKey, nil, reqMd, rsaKey)
	assert.NoError(t, err)
	assert.True(t, reqMd.SameAs(md))
}

func Test_CreateKeyEncryptedMessage_Locking(t *testing.T) {
	reqMd := core.SecondaryProtectionParameters{
		CreateLimit:         100,
		Expiry:              200,
		ProviderConstraints: []core.ProviderConstraint{"acceptance"},
		NumUses:             300,
	}

	lockCoord := &core.AzKeyVaultObjectCoordinate{
		VaultName: "vaultName",
		Name:      "key",
		Type:      "keys",
	}

	privKey, privKeyErr := AcquireJWT(testkeymaterial.EphemeralRsaKeyText, "")
	assert.NoError(t, privKeyErr)

	rsaKey, err := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.NoError(t, err)

	_, md, err := CreateKeyEncryptedMessage(privKey, lockCoord, reqMd, rsaKey)
	assert.NoError(t, err)
	assert.False(t, reqMd.SameAs(md))
	assert.Equal(t, 1, len(md.PlacementConstraints))
	assert.Equal(t,
		"az-c-keyvault://vaultName@keys=key",
		string(md.PlacementConstraints[0]))
}

func Test_CreateKeyEncryptedMessage_EncryptedMessage_Pem(t *testing.T) {
	exerciseCreateKeyEncryptedMessageCycle(
		t,
		testkeymaterial.EphemeralRsaKeyText,
		"",
		func(i interface{}) bool { _, ok := i.(jwk.RSAPrivateKey); return ok },
	)
}

func Test_CreateKeyEncryptedMessage_EncryptedMessage_PemPassword(t *testing.T) {
	exerciseCreateKeyEncryptedMessageCycle(
		t,
		testkeymaterial.EphemeralEncryptedRsaKeyText,
		"s1cr3t",
		func(i interface{}) bool { _, ok := i.(jwk.RSAPrivateKey); return ok },
	)
}

func Test_CreateKeyEncryptedMessage_EncryptedMessage_DER(t *testing.T) {
	exerciseCreateKeyEncryptedMessageCycle(
		t,
		testkeymaterial.EphemeralRsaKeyDERForm,
		"",
		func(i interface{}) bool { _, ok := i.(jwk.RSAPrivateKey); return ok },
	)
}

func Test_CreateKeyEncryptedMessage_EncryptedMessage_DEREncrypted(t *testing.T) {
	exerciseCreateKeyEncryptedMessageCycle(
		t,
		testkeymaterial.EphemeralRsaKeyDERForm,
		"s1cr3t",
		func(i interface{}) bool { _, ok := i.(jwk.RSAPrivateKey); return ok },
	)
}

func Test_CreateKeyEncryptedMessage_EncryptedMessage_EC(t *testing.T) {
	exerciseCreateKeyEncryptedMessageCycle(
		t,
		testkeymaterial.Prime256v1EcPrivateKey,
		"",
		func(i interface{}) bool { _, ok := i.(jwk.ECDSAPrivateKey); return ok },
	)
}

func exerciseCreateKeyEncryptedMessageCycle(t *testing.T, key []byte, password string, typeChecker core.Mapper[interface{}, bool]) {
	reqMd := core.SecondaryProtectionParameters{
		CreateLimit:         100,
		Expiry:              200,
		ProviderConstraints: []core.ProviderConstraint{"acceptance"},
		NumUses:             300,
	}

	lockCoord := &core.AzKeyVaultObjectCoordinate{
		VaultName: "vaultName",
		Name:      "key",
		Type:      "keys",
	}

	privKey, privKeyErr := AcquireJWT(key, password)
	assert.NoError(t, privKeyErr)

	rsaKey, err := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.NoError(t, err)

	rsaPrivKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	em, _, err := CreateKeyEncryptedMessage(privKey, lockCoord, reqMd, rsaKey)
	assert.NoError(t, err)

	ciphertext := em.ToBase64PEM()
	rbEm := core.EncryptedMessage{}

	err = rbEm.FromBase64PEM(ciphertext)
	assert.NoError(t, err)

	hdr, rbKey, err := DecryptKeyMessage(
		em,
		func(bytes []byte) ([]byte, error) {
			return core.RsaDecryptBytes(rsaPrivKey.(*rsa.PrivateKey), bytes, nil)
		},
	)

	assert.NoError(t, err)
	assert.NotNil(t, rbKey)

	isRsaKey := typeChecker(rbKey)
	assert.True(t, isRsaKey)

	assert.Equal(t, int64(100), hdr.CreateLimit)
	assert.Equal(t, int64(200), hdr.Expiry)
	assert.Equal(t, 300, hdr.NumUses)
	assert.True(t, core.SameBag(
		func(a, b core.ProviderConstraint) bool { return a == b },
		[]core.ProviderConstraint{"acceptance"},
		hdr.ProviderConstraints,
	))
	assert.Equal(t,
		core.PlacementConstraint("az-c-keyvault://vaultName@keys=key"),
		hdr.PlacementConstraints[0],
	)
}
