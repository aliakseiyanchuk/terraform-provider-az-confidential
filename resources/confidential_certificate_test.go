package resources

import (
	"context"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func Test_CAzVCR_DoUpdate_ImplicitMove(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.On("GetDestinationVaultObjectCoordinate", mock.Anything, "certificates").Return(core.AzKeyVaultObjectCoordinate{
		VaultName: "movedVault",
		Name:      "keyName",
		Type:      "certificates",
	})

	r := ConfidentialAzVaultCertificateResource{}
	r.factory = &factory

	stateData := ConfidentialCertificateModel{}
	stateData.Id = types.StringValue("https://cfg-vault.vaults.unittests/certificates/certName/certVersion")

	planData := ConfidentialCertificateModel{
		DestinationCert: core.AzKeyVaultObjectCoordinateModel{
			Name: types.StringValue("certName"),
		},
	}

	resp := resource.UpdateResponse{}

	rv := r.DoUpdate(context.Background(), &stateData, &planData, &resp)
	assert.True(t, resp.Diagnostics.HasError())
	assert.Equal(t, "Implicit object move", resp.Diagnostics[0].Summary())
	assert.Equal(t, DoNotFlushState, rv)
}
