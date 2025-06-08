package resources

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetDestinationSecretCoordinateFromId(t *testing.T) {
	v := ConfidentialSecretModel{}
	v.Id = types.StringValue("https://myvaultname.vault.azure.net/keys/key1053998307/b86c2e6ad9054f4abf69cc185b99aa60")

	coord, err := v.GetDestinationSecretCoordinateFromId()
	assert.Nil(t, err)
	assert.Equal(t, "myvaultname", coord.VaultName)
	assert.Equal(t, "key1053998307", coord.Name)
	assert.Equal(t, "b86c2e6ad9054f4abf69cc185b99aa60", coord.Version)
}
