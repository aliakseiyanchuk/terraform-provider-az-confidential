package general

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
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

func Test_Content_CheckUnpackCondition_IfCiphertextExpired(t *testing.T) {
	ds := ConfidentialContentDataSource{}
	dg := diag.Diagnostics{}

	hdr := core.ConfidentialDataJsonHeader{
		Expiry: time.Now().Unix() - 10,
	}

	ds.CheckUnpackCondition(context.Background(), hdr, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Ciphertext has expired", dg[0].Summary())
}

func Test_Content_CheckUnpackCondition_IfPlacementIsNotPossible(t *testing.T) {
	mock := FactoryMock{}
	ds := ConfidentialContentDataSource{}
	ds.Factory = &mock

	dg := diag.Diagnostics{}

	hdr := core.ConfidentialDataJsonHeader{
		Expiry: time.Now().Unix() + 60*24*60*60,
	}

	mock.GivenEnsureCanPlaceLabelledObjectAtRaisesError(ContentObjectType)

	ds.CheckUnpackCondition(context.Background(), hdr, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Can't place object unit test error", dg[0].Summary())

	mock.AssertExpectations(t)
}

func Test_Content_CheckUnpackCondition_IfNumberOfUserForUnconfiguredFactory(t *testing.T) {
	mock := FactoryMock{}
	ds := ConfidentialContentDataSource{}
	ds.Factory = &mock

	dg := diag.Diagnostics{}

	hdr := core.ConfidentialDataJsonHeader{
		Expiry:  time.Now().Unix() + 60*24*60*60,
		NumUses: 10,
	}

	mock.GivenEnsureCanPlaceLabelledObject(ContentObjectType)
	mock.GivenIsObjectTrackingEnabled(false)

	ds.CheckUnpackCondition(context.Background(), hdr, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Object tracking is not enabled", dg[0].Summary())

	mock.AssertExpectations(t)
}

func Test_Content_CheckUnpackCondition_IfNumberOfUsesErrs(t *testing.T) {
	mock := FactoryMock{}
	ds := ConfidentialContentDataSource{}
	ds.Factory = &mock

	dg := diag.Diagnostics{}

	hdr := core.ConfidentialDataJsonHeader{
		Uuid:    "uuid",
		Expiry:  time.Now().Unix() + 60*24*60*60,
		NumUses: 10,
	}

	mock.GivenEnsureCanPlaceLabelledObject(ContentObjectType)
	mock.GivenIsObjectTrackingEnabled(true)
	mock.GivenGetTackedObjectUsesErrs("uuid", "uses-unit-test-error")

	ds.CheckUnpackCondition(context.Background(), hdr, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Object tracking errored", dg[0].Summary())

	mock.AssertExpectations(t)
}

func Test_Content_CheckUnpackCondition_IfUsesDepleted(t *testing.T) {
	mock := FactoryMock{}
	ds := ConfidentialContentDataSource{}
	ds.Factory = &mock

	dg := diag.Diagnostics{}

	hdr := core.ConfidentialDataJsonHeader{
		Uuid:    "uuid",
		Expiry:  time.Now().Unix() + 60*24*60*60,
		NumUses: 10,
	}

	mock.GivenEnsureCanPlaceLabelledObject(ContentObjectType)
	mock.GivenIsObjectTrackingEnabled(true)
	mock.GivenGetTackedObjectUses("uuid", 10)

	ds.CheckUnpackCondition(context.Background(), hdr, &dg)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Content usage limit has been reached", dg[0].Summary())

	mock.AssertExpectations(t)
}

func Test_Content_CheckUnpackCondition_IfUsesAlmostDepleted(t *testing.T) {
	mock := FactoryMock{}
	ds := ConfidentialContentDataSource{}
	ds.Factory = &mock

	dg := diag.Diagnostics{}

	hdr := core.ConfidentialDataJsonHeader{
		Uuid:    "uuid",
		Expiry:  time.Now().Unix() + 60*24*60*60,
		NumUses: 10,
	}

	mock.GivenEnsureCanPlaceLabelledObject(ContentObjectType)
	mock.GivenIsObjectTrackingEnabled(true)
	mock.GivenGetTackedObjectUses("uuid", 5)

	ds.CheckUnpackCondition(context.Background(), hdr, &dg)
	assert.False(t, dg.HasError())
	assert.Equal(t, "Content use is almost depleted", dg[0].Summary())
	assert.Equal(t, "Warning", dg[0].Severity().String())

	mock.AssertExpectations(t)
}
