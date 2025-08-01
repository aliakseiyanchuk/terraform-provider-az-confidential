package general

import (
	"context"
	"crypto/rsa"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfidentialContentModelAcceptTest(t *testing.T) {
	md := core.SecondaryProtectionParameters{}
	mdl := ConfidentialContentModel{}

	helper := core.NewVersionedStringConfidentialDataHelper(ContentObjectType)
	bObj := helper.CreateConfidentialStringData("abc", md)

	mdl.Accept(bObj.Header.Uuid, bObj.Data)
	assert.Equal(t, bObj.Header.Uuid, mdl.Id.ValueString())
	assert.Equal(t, bObj.Data.GetStingData(), mdl.Plaintext.ValueString())
	assert.Equal(t, "YWJj", mdl.PlaintextBase64.ValueString())
	assert.Equal(t, "616263", mdl.PlaintextHex.ValueString())
}

func Test_CPDS_WillReadSchema(t *testing.T) {
	cm := ConfidentialContentDataSource{}

	schReq := datasource.SchemaRequest{}
	schResp := datasource.SchemaResponse{}

	cm.Schema(context.Background(), schReq, &schResp)
	assert.False(t, schResp.Diagnostics.HasError())
}

func Test_NewPasswordEncryptionFunction_WillReturn(t *testing.T) {
	fn := NewPasswordEncryptionFunction()
	assert.NotNil(t, fn)
}

func Test_NewConfidentialPasswordDataSource_WillReturn(t *testing.T) {
	r := NewConfidentialPasswordDataSource()
	assert.NotNil(t, r)
}

func Test_CreateContentEncryptedMessage_EncryptedMessage(t *testing.T) {
	reqMd := core.SecondaryProtectionParameters{
		CreateLimit:         100,
		Expiry:              200,
		ProviderConstraints: []core.ProviderConstraint{"acceptance"},
		NumUses:             300,
	}

	rsaKey, err := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.NoError(t, err)

	rsaPrivKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.NoError(t, err)

	em, err := CreateContentEncryptedMessage("this is a secret content", reqMd, rsaKey)
	assert.NoError(t, err)

	ciphertext := em.ToBase64PEM()
	rbEm := core.EncryptedMessage{}

	err = rbEm.FromBase64PEM(ciphertext)
	assert.NoError(t, err)

	hdr, msg, err := DecryptContentMessage(
		em,
		func(bytes []byte) ([]byte, error) {
			return core.RsaDecryptBytes(rsaPrivKey.(*rsa.PrivateKey), bytes, nil)
		},
	)

	assert.NoError(t, err)
	assert.Equal(t, "this is a secret content", msg.GetStingData())
	assert.Equal(t, int64(100), hdr.CreateLimit)
	assert.Equal(t, int64(200), hdr.Expiry)
	assert.Equal(t, 300, hdr.NumUses)
	assert.True(t, core.SameBag(
		func(a, b core.ProviderConstraint) bool { return a == b },
		[]core.ProviderConstraint{"acceptance"},
		hdr.ProviderConstraints,
	))
	assert.Nil(t, hdr.PlacementConstraints)
}
