package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_WKC_Validate(t *testing.T) {
	wkc := WrappingKeyCoordinate{}

	dg := wkc.Validate()
	assert.True(t, dg.HasError())

	wkc.VaultName = "vault"
	dg = wkc.Validate()
	assert.True(t, dg.HasError())

	wkc.VaultName = ""
	wkc.KeyName = "secret"
	dg = wkc.Validate()
	assert.True(t, dg.HasError())

	wkc.VaultName = "vault"
	dg = wkc.Validate()
	assert.False(t, dg.HasError())
}
