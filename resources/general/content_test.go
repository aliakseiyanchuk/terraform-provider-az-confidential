package general

import (
	"context"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfidentialPasswordModelAcceptTest(t *testing.T) {
	md := core.VersionedConfidentialMetadata{
		ObjectType: PasswordObjectType,
	}
	mdl := ConfidentialContentModel{}

	helper := core.NewVersionedStringConfidentialDataHelper()
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
