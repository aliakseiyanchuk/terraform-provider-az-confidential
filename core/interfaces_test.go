package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_WKC_Validate(t *testing.T) {
	wkc := WrappingKeyCoordinate{}

	dg := wkc.Validate()
	assert.Error(t, dg)

	wkc.VaultName = "vault"
	dg = wkc.Validate()
	assert.Error(t, dg)

	wkc.VaultName = ""
	wkc.KeyName = "secret"
	dg = wkc.Validate()
	assert.Error(t, dg)

	wkc.VaultName = "vault"
	wkc.KeyName = "secret"
	dg = wkc.Validate()
	assert.NoError(t, dg)
}

func Test_AzKVOVC_SameAs(t *testing.T) {
	this := AzKeyVaultObjectVersionedCoordinate{
		Version: "1",
		AzKeyVaultObjectCoordinate: AzKeyVaultObjectCoordinate{
			VaultName: "vaultHost",
			Name:      "objectName",
			Type:      "keyType",
		},
	}

	assert.True(t, this.SameAs(this.Clone()))

	other := this.Clone()
	other.Version = "2"
	assert.False(t, this.SameAs(other))

	other = this.Clone()
	other.VaultName = this.VaultName + "@"
	assert.False(t, this.SameAs(other))

	other = this.Clone()
	other.Name = this.VaultName + "@"
	assert.False(t, this.SameAs(other))

	other = this.Clone()
	other.Name = this.Type + "@"
	assert.False(t, this.SameAs(other))
}
