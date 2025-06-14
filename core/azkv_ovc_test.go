package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetCoordinateFromId(t *testing.T) {
	v := AzKeyVaultObjectVersionedCoordinate{}
	err := v.FromId("https://myvaultname.vault.azure.net/keys/key1053998307/b86c2e6ad9054f4abf69cc185b99aa60")
	assert.Nil(t, err)

	assert.Equal(t, "myvaultname", v.VaultName)
	assert.Equal(t, "key1053998307", v.Name)
	assert.Equal(t, "keys", v.Type)
	assert.Equal(t, "b86c2e6ad9054f4abf69cc185b99aa60", v.Version)
}
func TestGetVersionlessCoordinateFromId(t *testing.T) {
	v := AzKeyVaultObjectVersionedCoordinate{}
	err := v.FromId("https://myvaultname.vault.azure.net/keys/key1053998307/b86c2e6ad9054f4abf69cc185b99aa60")
	assert.Nil(t, err)

	assert.Equal(t, "https://myvaultname.vault.azure.net/keys/key1053998307", v.VersionlessId())
}
