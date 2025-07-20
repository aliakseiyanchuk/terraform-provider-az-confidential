package general

import (
	"context"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfidentialPasswordModelAcceptTest(t *testing.T) {
	mdl := ConfidentialPasswordModel{}

	helper := core.NewVersionedStringConfidentialDataHelper()
	bObj := helper.CreateConfidentialStringData("abc", "password", nil)

	mdl.Accept(bObj.Header.Uuid, bObj.Data)
	assert.Equal(t, bObj.Header.Uuid, mdl.Id.ValueString())
	assert.Equal(t, bObj.Data.GetStingData(), mdl.PlaintextPassword.ValueString())
	assert.Equal(t, "YWJj", mdl.PlaintextPasswordBase64.ValueString())
	assert.Equal(t, "616263", mdl.PlaintextPasswordHex.ValueString())
}

func Test_CPDS_WillReadSchema(t *testing.T) {
	cm := ConfidentialPasswordDataSource{}

	schReq := datasource.SchemaRequest{}
	schResp := datasource.SchemaResponse{}

	cm.Schema(context.Background(), schReq, &schResp)
	assert.False(t, schResp.Diagnostics.HasError())
}
