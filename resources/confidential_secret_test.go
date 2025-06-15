package resources

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
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
