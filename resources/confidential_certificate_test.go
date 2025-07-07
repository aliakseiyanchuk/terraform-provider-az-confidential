package resources

import (
	"context"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CAzVCR_DoRead_IfCertWasNeverCreated(t *testing.T) {
	ks := AzKeyVaultCertificateResourceSpecializer{}

	data := ConfidentialCertificateModel{}
	data.Id = types.StringUnknown()

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.False(t, dg.HasError())
	assert.Equal(t, ResourceNotYetCreated, v)
}

func Test_CAzVCR_DoRead_IfCertIdIsMalformed(t *testing.T) {
	ks := AzKeyVaultCertificateResourceSpecializer{}

	data := ConfidentialCertificateModel{}
	data.Id = types.StringValue("this is not a valid id")

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot establish reference to the created certificate version", dg[0].Summary())
	assert.Equal(t, ResourceCheckError, v)
}

func GivenTypicalConfidentialCertificateModel() ConfidentialCertificateModel {
	mdl := ConfidentialCertificateModel{}

	mdl.Id = types.StringValue("https://unit-test-vault/certificates/certName/certVersion")
	return mdl
}

func Test_CAzVCR_DoRead_IfCertificatesClientCannotConnect(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturnError("unit-test-vault", "unit-test-error-message")
	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := GivenTypicalConfidentialCertificateModel()

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire certificates client", dg[0].Summary())
	assert.Equal(t, ResourceCheckError, v)

	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoRead_IfCertificatesClientIsNil(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturnNilClient("unit-test-vault")
	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := GivenTypicalConfidentialCertificateModel()

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire certificates client", dg[0].Summary())
	assert.Equal(t, ResourceCheckError, v)

	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoRead_WhenCertNotFoundAndTrackingEnabled(t *testing.T) {
	certClient := CertificateClientMock{}
	certClient.GivenGetCertificateReturnsObjectNotFound("certName", "certVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &certClient)
	factory.GivenIsObjectTrackingEnabled(true)
	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := GivenTypicalConfidentialCertificateModel()

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.False(t, dg.HasError())
	assert.Equal(t, "Warning", dg[0].Severity().String())
	assert.Equal(t, "Certificate removed from key vault", dg[0].Summary())
	assert.Equal(t, ResourceNotFound, v)

	factory.AssertExpectations(t)
	certClient.AssertExpectations(t)
}

func Test_CAzVCR_DoRead_WhenCertNotFoundAndTrackingDisabled(t *testing.T) {
	certClient := CertificateClientMock{}
	certClient.GivenGetCertificateReturnsObjectNotFound("certName", "certVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &certClient)
	factory.GivenIsObjectTrackingEnabled(false)
	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := GivenTypicalConfidentialCertificateModel()

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.False(t, dg.HasError())
	assert.Equal(t, 0, len(dg))
	assert.Equal(t, ResourceNotFound, v)

	factory.AssertExpectations(t)
	certClient.AssertExpectations(t)
}

func Test_CAzVCR_DoRead_WhenReadingCertReturnsError(t *testing.T) {
	certClient := CertificateClientMock{}
	certClient.GivenGetCertificateErrs("certName", "certVersion", "unit-test-error")

	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &certClient)
	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := GivenTypicalConfidentialCertificateModel()

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot read certificate", dg[0].Summary())
	assert.Equal(t, ResourceCheckError, v)

	factory.AssertExpectations(t)
	certClient.AssertExpectations(t)
}

func Test_CAzVCR_DoRead(t *testing.T) {
	certClient := CertificateClientMock{}
	certClient.GivenGetCertificate("certName", "certVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &certClient)
	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := GivenTypicalConfidentialCertificateModel()

	_, v, dg := ks.DoRead(context.Background(), &data)
	assert.False(t, dg.HasError())
	assert.Equal(t, ResourceExists, v)

	factory.AssertExpectations(t)
	certClient.AssertExpectations(t)
}

func Test_CAzVCR_DoCreate_NoPayload(t *testing.T) {
	ks := AzKeyVaultCertificateResourceSpecializer{}

	data := ConfidentialCertificateModel{}
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper()

	var emptyBytes []byte
	confData := helper.CreateConfidentialCertificateData(emptyBytes, "something", "", "certificate", nil)

	_, dg := ks.DoCreate(context.Background(), &data, confData)
	assert.True(t, dg.HasError())
}

func GivenTypicalInitialCertModel() ConfidentialCertificateModel {
	mdl := ConfidentialCertificateModel{
		DestinationCert: core.AzKeyVaultObjectCoordinateModel{
			Name:      types.StringValue("certName"),
			VaultName: types.StringValue("unit-test-vault"),
		},
	}

	return mdl
}

func Test_CAzVCR_DoCreate_IfCertificateClientCannotConnect(t *testing.T) {

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturnError("unit-test-vault", "unit-test-error")

	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := ConfidentialCertificateModel{}
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper()
	confData := helper.CreateConfidentialCertificateData(testkeymaterial.EphemeralCertificatePEM, "application/x-pem-file", "", "certificate", nil)

	_, dg := ks.DoCreate(context.Background(), &data, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Error acquiring certificates client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoCreate_IfCertificateClientIsNil(t *testing.T) {

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturnNilClient("unit-test-vault")

	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := ConfidentialCertificateModel{}
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper()
	confData := helper.CreateConfidentialCertificateData(testkeymaterial.EphemeralCertificatePEM, "application/x-pem-file", "", "certificate", nil)

	_, dg := ks.DoCreate(context.Background(), &data, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Az certificates vault keys client cannot be retrieved", dg[0].Summary())

	factory.AssertExpectations(t)
}
func Test_CAzVCR_DoCreate_IfCertificateImportFails(t *testing.T) {

	certClient := CertificateClientMock{}
	certClient.GivenImportCertificateErrs("certName", "unit-test-cert-import-error")

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &certClient)

	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := ConfidentialCertificateModel{}
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper()
	confData := helper.CreateConfidentialCertificateData(testkeymaterial.EphemeralCertificatePEM, "application/x-pem-file", "", "certificate", nil)

	_, dg := ks.DoCreate(context.Background(), &data, confData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Certificate import failed", dg[0].Summary())

	certClient.AssertExpectations(t)
	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoCreate(t *testing.T) {

	certClient := CertificateClientMock{}
	certClient.GivenImportCertificate("certName")

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &certClient)

	ks := AzKeyVaultCertificateResourceSpecializer{
		factory: &factory,
	}

	data := GivenTypicalInitialCertModel()
	helper := core.NewVersionedKeyVaultCertificateConfidentialDataHelper()
	confData := helper.CreateConfidentialCertificateData(testkeymaterial.EphemeralCertificatePEM, "application/x-pem-file", "", "certificate", nil)

	_, dg := ks.DoCreate(context.Background(), &data, confData)
	assert.False(t, dg.HasError())

	factory.AssertExpectations(t)
	certClient.AssertExpectations(t)
}

func Test_CAzVCR_DoUpdate_WhenIdIsMalformed(t *testing.T) {
	mdl := ConfidentialCertificateModel{}
	mdl.Id = types.StringValue("this is not a valid identifier")

	ks := AzKeyVaultCertificateResourceSpecializer{}
	_, df := ks.DoUpdate(context.Background(), &mdl)
	assert.True(t, df.HasError())
	assert.Equal(t, "Error getting previously created certificate coordinate", df[0].Summary())
}

func Test_CAzVCR_DoUpdate_ImplicitMove(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("movedVault", "certificates", "certificates")

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := ConfidentialCertificateModel{
		DestinationCert: core.AzKeyVaultObjectCoordinateModel{
			Name: types.StringValue("certName"),
		},
	}
	planData.Id = types.StringValue("https://cfg-vault.vaults.unittests/certificates/certName/certVersion")

	_, dg := r.DoUpdate(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Implicit object move", dg[0].Summary())

	factory.AssertExpectations(t)
}

func givenExistingCertificateModel() ConfidentialCertificateModel {
	planData := ConfidentialCertificateModel{
		DestinationCert: core.AzKeyVaultObjectCoordinateModel{
			Name: types.StringValue("certName"),
		},
	}
	planData.Id = types.StringValue("https://unit-test-vault/certificates/certName/certVersion")

	return planData
}

func Test_CAzVCR_DoUpdate_WhenCertClientCannotConnect(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturnError("unit-test-vault", "unit-test-error")

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	_, dg := r.DoUpdate(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire cert client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoUpdate_WhenCertClientIsNil(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturnNilClient("unit-test-vault")

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	_, dg := r.DoUpdate(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire cert client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoUpdate_WhenUpdateError(t *testing.T) {
	clientMock := CertificateClientMock{}
	clientMock.GivenUpdateCertificateErrs("certName", "certVersion", "unit-test-error")

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &clientMock)

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	_, dg := r.DoUpdate(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Error updating certificate properties", dg[0].Summary())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVCR_DoUpdate(t *testing.T) {
	clientMock := CertificateClientMock{}
	clientMock.GivenUpdateCertificate("certName", "certVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetDestinationVaultObjectCoordinate("unit-test-vault", "certificates", "certName")
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &clientMock)

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	_, dg := r.DoUpdate(context.Background(), &planData)
	assert.False(t, dg.HasError())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVCR_DoDelete_WhenIdIsMalformed(t *testing.T) {
	mdl := ConfidentialCertificateModel{}
	mdl.Id = types.StringValue("this is not a valid identifier")

	ks := AzKeyVaultCertificateResourceSpecializer{}
	df := ks.DoDelete(context.Background(), &mdl)
	assert.True(t, df.HasError())
	assert.Equal(t, "Error getting previously created certificate coordinate", df[0].Summary())
}

func Test_CAzVCR_DoDelete_WhenCertClientCannotConnect(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturnError("unit-test-vault", "unit-test-error")

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	dg := r.DoDelete(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire certificate client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoDelete_WhenCertClientIsNil(t *testing.T) {
	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturnNilClient("unit-test-vault")

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	dg := r.DoDelete(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot acquire certificate client", dg[0].Summary())

	factory.AssertExpectations(t)
}

func Test_CAzVCR_DoDelete_WhenUpdateError(t *testing.T) {
	clientMock := CertificateClientMock{}
	clientMock.GivenUpdateCertificateErrs("certName", "certVersion", "unit-test-error")

	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &clientMock)

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	dg := r.DoDelete(context.Background(), &planData)
	assert.True(t, dg.HasError())
	assert.Equal(t, "Cannot disable cert version", dg[0].Summary())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func Test_CAzVCR_DoDelete(t *testing.T) {
	clientMock := CertificateClientMock{}
	clientMock.GivenUpdateCertificate("certName", "certVersion")

	factory := AZClientsFactoryMock{}
	factory.GivenGetCertificatesClientWillReturn("unit-test-vault", &clientMock)

	r := AzKeyVaultCertificateResourceSpecializer{}
	r.factory = &factory

	planData := givenExistingCertificateModel()

	dg := r.DoDelete(context.Background(), &planData)
	assert.False(t, dg.HasError())

	factory.AssertExpectations(t)
	clientMock.AssertExpectations(t)
}

func TestNewConfidentialAzVaultCertificateResourceWillReturn(t *testing.T) {
	// Test that the new az key vault resource would not crash on start-up
	_ = NewConfidentialAzVaultCertificateResource()
}
