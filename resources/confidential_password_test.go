package resources

import (
	"encoding/base64"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfidentialPasswordModelAcceptTest(t *testing.T) {
	mdl := ConfidentialPasswordModel{}

	v := core.VersionedConfidentialData{
		Uuid:       "a-b-c-d",
		StringData: "abc",
	}

	mdl.Accept(v)
	assert.Equal(t, "a-b-c-d", mdl.Id.ValueString())
	assert.Equal(t, "abc", mdl.PlaintextPassword.ValueString())
	assert.Equal(t, "YWJj", mdl.PlaintextPasswordBase64.ValueString())
	assert.Equal(t, "616263", mdl.PlaintextPasswordHex.ValueString())
}
func TestConfidentialPasswordModelAcceptBinary(t *testing.T) {
	mdl := ConfidentialPasswordModel{}

	b, err := base64.StdEncoding.DecodeString("YWJj")
	assert.Nil(t, err)

	v := core.VersionedConfidentialData{
		Uuid:       "a-b-c-d",
		BinaryData: b,
	}

	mdl.Accept(v)
	assert.Equal(t, "a-b-c-d", mdl.Id.ValueString())
	assert.True(t, mdl.PlaintextPassword.IsNull())
	assert.Equal(t, "YWJj", mdl.PlaintextPasswordBase64.ValueString())
	assert.Equal(t, "616263", mdl.PlaintextPasswordHex.ValueString())
}
