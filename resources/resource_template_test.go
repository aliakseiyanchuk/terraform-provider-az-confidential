package resources

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type ParamMatcher[TValue any] func(req TValue) bool

func StringPtrMatcher(expectedValue string) ParamMatcher[*string] {
	return func(req *string) bool {
		return req != nil && *req == expectedValue
	}
}

func PtrMatcher[T any](expectedValue T, comparator core.Comparator[T]) ParamMatcher[*T] {
	return func(req *T) bool {
		return req != nil && comparator(*req, expectedValue)
	}
}

func StringComparator(a, b string) bool { return a == b }

type AZClientsFactoryMock struct {
	mock.Mock
	core.AZClientsFactory
}

func (azm *AZClientsFactoryMock) GetMergedWrappingKeyCoordinate(ctx context.Context, param *core.WrappingKeyCoordinateModel, diag *diag.Diagnostics) core.WrappingKeyCoordinate {
	args := azm.Called(ctx, param, diag)
	return args.Get(0).(core.WrappingKeyCoordinate)
}

func (azm *AZClientsFactoryMock) GetDecrypterFor(ctx context.Context, coord *core.WrappingKeyCoordinateModel) core.RSADecrypter {
	args := azm.Called(ctx, coord)
	return args.Get(0).(core.RSADecrypter)
}

func (azm *AZClientsFactoryMock) IsObjectTrackingEnabled() bool {
	args := azm.Called()
	return args.Get(0).(bool)
}

func (azm *AZClientsFactoryMock) GetTackedObjectUses(ctx context.Context, uuid string) (int, error) {
	args := azm.Called(ctx, uuid)
	return args.Int(0), args.Error(1)
}

func (azm *AZClientsFactoryMock) TrackObjectId(ctx context.Context, uuid string) error {
	args := azm.Called(ctx, uuid)
	return args.Error(0)
}

func (azm *AZClientsFactoryMock) GivenObjectTrackingConfigured(how bool) {
	azm.On("IsObjectTrackingEnabled").Return(how)
}

func (azm *AZClientsFactoryMock) GivenGetTackedObjectUsesErrs(errMsg string) {
	azm.On("GetTackedObjectUses", mock.Anything, mock.Anything).Return(0, errors.New(errMsg))
}

func (azm *AZClientsFactoryMock) GivenGetTackedObjectUses(n int) {
	azm.On("GetTackedObjectUses", mock.Anything, mock.Anything).
		Return(n, nil).Once()

	azm.On("GetTackedObjectUses", mock.Anything, mock.Anything).
		Return(n+1, nil).Maybe()
}

func (azm *AZClientsFactoryMock) GivenTrackObjectIdErrs() {
	azm.On("TrackObjectId", mock.Anything, mock.Anything).Return(errors.New("unit-test-tracking-error"))
}

func (azm *AZClientsFactoryMock) GivenTrackObject() {
	azm.On("TrackObjectId", mock.Anything, mock.Anything).Return(nil)
}

type TerraformRequestMock struct {
	mock.Mock

	Diagnostic *diag.Diagnostics
}

func (s *TerraformRequestMock) Set(ctx context.Context, val interface{}) diag.Diagnostics {
	args := s.Mock.Called(ctx, val)
	return args.Get(0).(diag.Diagnostics)
}

func (s *TerraformRequestMock) GivenSet() {
	s.On("Set", mock.Anything, mock.Anything).
		Return(nil)
}

func (s *TerraformRequestMock) RemoveResource(ctx context.Context) {
	_ = s.Mock.Called(ctx)
}

func (s *TerraformRequestMock) GivenResourceWillBeRemoved() {
	s.On("RemoveResource", mock.Anything).Once()
}

func (s *TerraformRequestMock) Get(ctx context.Context, val interface{}) diag.Diagnostics {
	args := s.Mock.Called(ctx, val)
	return args.Get(0).(diag.Diagnostics)
}

func (s *TerraformRequestMock) GivenGet() {
	s.On("Get", mock.Anything, mock.Anything).
		Return(diag.Diagnostics{})
}

func (s *TerraformRequestMock) GivenGetDiagnosesError(expValue interface{}, msg string) {
	rv := diag.Diagnostics{}
	rv.AddError(msg, "unit-test-summary")

	s.On("Get", mock.Anything, expValue).
		Return(rv)
}

func (s *TerraformRequestMock) AsRequestAbstraction() RequestAbstraction {
	return RequestAbstraction{
		Get: s.Get,
	}
}

func (s *TerraformRequestMock) AsResponseAbstraction() ResponseAbstraction {
	return ResponseAbstraction{
		Set:            s.Set,
		RemoveResource: s.RemoveResource,
		Diagnostics:    s.Diagnostic,
	}
}

func (s *TerraformRequestMock) ThenTerraformModelIsSet(modelValue string) {
	s.On("Set", mock.Anything, mock.MatchedBy(PtrMatcher(modelValue, StringComparator))).
		Once().
		Return(diag.Diagnostics{})
}

func (s *TerraformRequestMock) ThenResourceIsRemoved() {
	s.On("RemoveResource", mock.Anything).Once()
}

type SpecializerMock[TMdl any, TConfData any, AZAPIObject any] struct {
	mock.Mock
	Factory core.AZClientsFactory
}

func (sm *SpecializerMock[TMdl, TConfData, AZAPIObject]) Decrypt(ctx context.Context, em core.EncryptedMessage, decr core.RSADecrypter) (core.ConfidentialDataJsonHeader, TConfData, error) {
	args := sm.Mock.Called(ctx, em, decr)
	return args.Get(0).(core.ConfidentialDataJsonHeader), args.Get(1).(TConfData), nil
}

func (sm *SpecializerMock[TMdl, TConfData, AZAPIObject]) GivenDecryptErrs(defaultValue TConfData, msg string) {
	sm.On("Decrypt", mock.Anything, mock.Anything, mock.Anything).Return(
		core.ConfidentialDataJsonHeader{},
		defaultValue,
		errors.New(msg))
}

func (sm *SpecializerMock[TMdl, TConfData, AZAPIObject]) GivenDecrypt(header core.ConfidentialDataJsonHeader, decryptedValue TConfData) {
	sm.On("Decrypt", mock.Anything, mock.Anything, mock.Anything).Return(
		header,
		decryptedValue,
		nil)
}

func (sm *SpecializerMock[TMdl, TConfData, AZAPIObject]) GivenCreateErrs(mdl, msg string) {
	sm.On("DoCreate",
		mock.Anything,
		mock.MatchedBy(PtrMatcher(mdl, StringComparator)),
		mock.Anything).
		Return(
			"ErrorAzureObject",
			diag.Diagnostics{
				diag.NewErrorDiagnostic(msg, "unit-test-details"),
			},
		)
}

func (sm *SpecializerMock[TMdl, TConfData, AZAPIObject]) GivenCreate(mdl string) {
	sm.On("DoCreate",
		mock.Anything,
		mock.MatchedBy(PtrMatcher(mdl, StringComparator)),
		mock.Anything).Return("CreatedAzureObject", diag.Diagnostics{})
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) SetFactory(f core.AZClientsFactory) {
	sm.Factory = f
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) NewTerraformModel() TMdl {
	args := sm.Called()
	return args.Get(0).(TMdl)
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) ConvertToTerraform(ctx context.Context, azObj AzAPIObject, tfModel *TMdl) diag.Diagnostics {
	args := sm.Called(ctx, azObj, tfModel)
	return args.Get(0).(diag.Diagnostics)
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) GetConfidentialMaterialFrom(mdl TMdl) ConfidentialMaterialModel {
	args := sm.Called(mdl)
	return args.Get(0).(ConfidentialMaterialModel)
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) GetSupportedConfidentialMaterialTypes() []string {
	args := sm.Called()
	return args.Get(0).([]string)
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) DoCreate(ctx context.Context, planData *TMdl, plainData TConfData) (AzAPIObject, diag.Diagnostics) {
	args := sm.Called(ctx, planData, plainData)
	return args.Get(0).(AzAPIObject), args[1].(diag.Diagnostics)
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) DoDelete(ctx context.Context, planData *TMdl) diag.Diagnostics {
	args := sm.Called(ctx, planData)
	return args.Get(0).(diag.Diagnostics)
}

func (sm *SpecializerMock[TMdl, TConfData, AzAPIObject]) CheckPlacement(ctx context.Context, providerConstraints []core.ProviderConstraint, placementConstraints []core.PlacementConstraint, tfModel *TMdl) diag.Diagnostics {
	args := sm.Called(ctx, providerConstraints, placementConstraints, tfModel)
	return args.Get(0).(diag.Diagnostics)
}

func (s *SpecializerMock[TMdl, TConfData, AzAPIObject]) ThenAzValueIsConvertedToTerraform(azValue AzAPIObject, modelValue TMdl, c core.Comparator[TMdl]) {
	s.On("ConvertToTerraform", mock.Anything, azValue, mock.MatchedBy(PtrMatcher(modelValue, c))).
		Once().
		Return(diag.Diagnostics{})
}

type ImmutableRUMock[TMdl, AZAPIObject any] struct {
	mock.Mock
}

func (im *ImmutableRUMock[TMdl, AZAPIObject]) DoRead(ctx context.Context, planData *TMdl) (AZAPIObject, ResourceExistenceCheck, diag.Diagnostics) {
	args := im.Called(ctx, planData)
	return args[0].(AZAPIObject), args[1].(ResourceExistenceCheck), args[2].(diag.Diagnostics)
}

func (im *ImmutableRUMock[TMdl, AZAPIObject]) DoUpdate(ctx context.Context, planData *TMdl) (AZAPIObject, diag.Diagnostics) {
	args := im.Called(ctx, planData)
	return args[0].(AZAPIObject), args[1].(diag.Diagnostics)
}

type MutableRUMock[TMdl, TConfData, AZAPIObject any] struct {
	mock.Mock
}

func (mm *MutableRUMock[TMdl, TConfData, AZAPIObject]) DoRead(ctx context.Context, planData *TMdl, plainData TConfData) (AZAPIObject, ResourceExistenceCheck, diag.Diagnostics) {
	args := mm.Called(ctx, planData, plainData)
	return args[0].(AZAPIObject), args[1].(ResourceExistenceCheck), diag.Diagnostics{}
}

func (mm *MutableRUMock[TMdl, TConfData, AZAPIObject]) DoUpdate(ctx context.Context, planData *TMdl, plainData TConfData) (AZAPIObject, diag.Diagnostics) {
	args := mm.Called(ctx, planData, plainData)
	return args[0].(AZAPIObject), args[1].(diag.Diagnostics)
}

func (mm *MutableRUMock[TMdl, TConfData, AZAPIObject]) SetDriftToConfidentialData(ctx context.Context, planData *TMdl) {
	_ = mm.Called(ctx, planData)
}

func (s *MutableRUMock[TMdl, TConfData, AZAPIObject]) ThenDriftWillBeSet(modelValue TMdl, c core.Comparator[TMdl]) {
	s.On("SetDriftToConfidentialData", mock.Anything, mock.MatchedBy(PtrMatcher(modelValue, c))).
		Once()
}

type GenericResourceTestContext struct {
	FactoryMock  *AZClientsFactoryMock
	RequestMock  *TerraformRequestMock
	ResponseMock *TerraformRequestMock

	ImmutableRU *ImmutableRUMock[string, string]
	MutableRU   *MutableRUMock[string, core.ConfidentialStringData, string]

	SpecializerMock   *SpecializerMock[string, core.ConfidentialStringData, string]
	ResourceUnderTest *ConfidentialGenericResource[string, int, core.ConfidentialStringData, string]
}

func (grtc *GenericResourceTestContext) GivenImmutableRUReturnsError(v string, errMsg string) {

	dg := diag.Diagnostics{
		diag.NewErrorDiagnostic(errMsg, "unit-test"),
	}

	iru := &ImmutableRUMock[string, string]{}
	iru.On(
		"DoRead",
		mock.Anything,
		mock.MatchedBy(StringPtrMatcher(v)),
	).Once().Return(
		"FailedModel",
		ResourceCheckError,
		dg,
	)

	grtc.ResourceUnderTest.ImmutableRU = iru
}

func (grtc *GenericResourceTestContext) GivenImmutableRUReturnsErrorWithoutDiagnostics(v string) {
	iru := &ImmutableRUMock[string, string]{}
	iru.On(
		"DoRead",
		mock.Anything,
		mock.MatchedBy(StringPtrMatcher(v)),
	).Once().Return(
		"FailedModel",
		ResourceCheckError,
		diag.Diagnostics{},
	)

	grtc.ResourceUnderTest.ImmutableRU = iru
}

const UnitTestObjectType = "unitTest/string"

func (grtc *GenericResourceTestContext) GivenObjectCanBePlacedAsRequested() {
	grtc.SpecializerMock.On("CheckPlacement",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.MatchedBy(StringPtrMatcher("InitialModelValue")),
	).Once().Return(diag.Diagnostics{})
}

func (grtc *GenericResourceTestContext) GivenObjectCannotBePlacedAsRequested(msg string) {
	grtc.SpecializerMock.On("CheckPlacement",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.MatchedBy(StringPtrMatcher("InitialModelValue")),
	).Once().Return(diag.Diagnostics{
		diag.NewErrorDiagnostic(msg, "unit-test-detail"),
	})
}

func (grtc *GenericResourceTestContext) GivenExpiredCiphertext(t *testing.T, mdl string) {
	md := core.SecondaryProtectionParameters{
		ProviderConstraints:  nil,
		PlacementConstraints: nil,
		CreateLimit:          0,
		Expiry:               time.Now().Unix() - 1000,
		NumUses:              0,
	}

	grtc.givenCiphertextOperations(t, mdl, md)

	if grtc.MutableRU == nil {
		grtc.MutableRU = &MutableRUMock[string, core.ConfidentialStringData, string]{}
	}
	grtc.ResourceUnderTest.MutableRU = grtc.MutableRU
}

func (grtc *GenericResourceTestContext) GivenExpiringCiphertext(t *testing.T, mdl string) {
	md := core.SecondaryProtectionParameters{
		ProviderConstraints:  nil,
		PlacementConstraints: nil,
		CreateLimit:          0,
		Expiry:               time.Now().Unix() + int64(time.Hour*24*29/time.Second),
		NumUses:              0,
	}

	grtc.givenCiphertextOperations(t, mdl, md)

	if grtc.MutableRU == nil {
		grtc.MutableRU = &MutableRUMock[string, core.ConfidentialStringData, string]{}
	}
	grtc.ResourceUnderTest.MutableRU = grtc.MutableRU
}

func (grtc *GenericResourceTestContext) GivenCiphertextExpiringIn3Months(t *testing.T, mdl string) {
	md := core.SecondaryProtectionParameters{
		ProviderConstraints:  nil,
		PlacementConstraints: nil,
		CreateLimit:          0,
		Expiry:               time.Now().Unix() + int64(time.Hour*24*31*3/time.Second),
		NumUses:              0,
	}

	grtc.givenCiphertextOperations(t, mdl, md)

	if grtc.MutableRU == nil {
		grtc.MutableRU = &MutableRUMock[string, core.ConfidentialStringData, string]{}
	}
	grtc.ResourceUnderTest.MutableRU = grtc.MutableRU
}

func (grtc *GenericResourceTestContext) GivenUseLimitedCiphertext(t *testing.T, mdl string, nUses int) {
	md := core.SecondaryProtectionParameters{
		ProviderConstraints:  nil,
		PlacementConstraints: nil,
		CreateLimit:          0,
		Expiry:               time.Now().Unix() + int64(time.Hour*24*31*3/time.Second),
		NumUses:              nUses,
	}

	grtc.givenCiphertextOperations(t, mdl, md)

	if grtc.MutableRU == nil {
		grtc.MutableRU = &MutableRUMock[string, core.ConfidentialStringData, string]{}
	}
	grtc.ResourceUnderTest.MutableRU = grtc.MutableRU
}

func (grtc *GenericResourceTestContext) givenCiphertextOperations(t *testing.T, mdl string, md core.SecondaryProtectionParameters) {
	helper := core.NewVersionedStringConfidentialDataHelper(UnitTestObjectType)
	_ = helper.CreateConfidentialStringData("this is a secret message", md)

	rsaKey, err := core.LoadPublicKeyFromData(testkeymaterial.EphemeralRsaPublicKey)
	assert.Nil(t, err, "Failed to load public key")

	privKey, err := core.PrivateKeyFromData(testkeymaterial.EphemeralRsaKeyText)
	assert.Nil(t, err, "Failed to load private key")

	em, err := helper.ToEncryptedMessage(rsaKey)
	assert.Nil(t, err, "Failed to encrypted message")

	cmm := ConfidentialMaterialModel{
		EncryptedSecret: types.StringValue(em.ToBase64PEM()),
	}

	var rsaDecrypter core.RSADecrypter
	rsaDecrypter = func(input []byte) ([]byte, error) { return core.RsaDecryptBytes(privKey.(*rsa.PrivateKey), input, nil) }

	grtc.SpecializerMock.On("GetConfidentialMaterialFrom", mdl).Return(cmm)
	grtc.SpecializerMock.
		On("Decrypt", mock.Anything, em, mock.AnythingOfType("core.RSADecrypter")).
		Return(helper.Header, helper.KnowValue, nil)

	grtc.FactoryMock.On("GetDecrypterFor", mock.Anything, mock.Anything).Return(rsaDecrypter).Maybe()
}

func (grtc *GenericResourceTestContext) GivenImmutableRUReturns(v string, state ResourceExistenceCheck) {

	dg := diag.Diagnostics{}

	iru := &ImmutableRUMock[string, string]{}
	iru.On(
		"DoRead",
		mock.Anything,
		mock.MatchedBy(StringPtrMatcher(v)),
	).Once().Return(
		"OkayModel",
		state,
		dg,
	)

	grtc.ResourceUnderTest.ImmutableRU = iru
}

func (grtc *GenericResourceTestContext) GivenMutableRUReturns(v string, state ResourceExistenceCheck) {

	dg := diag.Diagnostics{}

	iru := &MutableRUMock[string, core.ConfidentialStringData, string]{}
	iru.On(
		"DoRead",
		mock.Anything,
		mock.MatchedBy(StringPtrMatcher(v)),
		mock.Anything,
	).Once().Return(
		"OkayModel",
		state,
		dg,
	)

	grtc.MutableRU = iru
	grtc.ResourceUnderTest.MutableRU = iru
}

func (grtc *GenericResourceTestContext) AssertResponseHasError(t *testing.T, errSummary string) {
	assert.True(t, grtc.ResponseMock.Diagnostic.HasError())

	found := false
	for _, dg := range *grtc.ResponseMock.Diagnostic {
		if dg.Summary() == errSummary && dg.Severity() == diag.SeverityError {
			found = true
			break
		}
	}

	assert.Truef(t, found, "Could not find error with summary %s", errSummary)
}

func (grtc *GenericResourceTestContext) AssertResponseHasWarning(t *testing.T, warnSummary string) {
	assert.False(t, grtc.ResponseMock.Diagnostic.HasError())

	found := false
	for _, dg := range *grtc.ResponseMock.Diagnostic {
		if dg.Summary() == warnSummary && dg.Severity() == diag.SeverityWarning {
			found = true
			break
		}
	}

	assert.Truef(t, found, "Could not find warning with summary %s", warnSummary)
}

func (grtc *GenericResourceTestContext) AssertResponseHasNoError(t *testing.T) {
	assert.False(t, grtc.ResponseMock.Diagnostic.HasError())
}

func (grtc *GenericResourceTestContext) AssertResponseHasNoWarnings(t *testing.T) {
	warnFound := false
	for _, dg := range *grtc.ResponseMock.Diagnostic {
		if dg.Severity() == diag.SeverityWarning {
			warnFound = true
			break
		}
	}

	assert.False(t, warnFound, "Diagnostic should not have any warnings")
}

func (grtc *GenericResourceTestContext) AssertExpectations(t *testing.T) {
	grtc.RequestMock.AssertExpectations(t)
	grtc.ResponseMock.AssertExpectations(t)
	grtc.SpecializerMock.AssertExpectations(t)
	grtc.FactoryMock.AssertExpectations(t)

	if grtc.ImmutableRU != nil {
		grtc.ImmutableRU.AssertExpectations(t)
	}

	if grtc.MutableRU != nil {
		grtc.MutableRU.AssertExpectations(t)
	}
}

func givenSetup() GenericResourceTestContext {
	factoryMock := &AZClientsFactoryMock{}
	sMock := &SpecializerMock[string, core.ConfidentialStringData, string]{
		Factory: factoryMock,
	}

	sMock.On("NewTerraformModel").Return("InitialModelValue").Once()

	cgr := ConfidentialGenericResource[string, int, core.ConfidentialStringData, string]{
		ConfidentialResourceBase: ConfidentialResourceBase{
			CommonConfidentialResource{
				Factory: factoryMock,
			},
		},
		Specializer: sMock,
	}

	return GenericResourceTestContext{
		FactoryMock: factoryMock,
		RequestMock: &TerraformRequestMock{},
		ResponseMock: &TerraformRequestMock{
			Diagnostic: &diag.Diagnostics{},
		},
		SpecializerMock:   sMock,
		ResourceUnderTest: &cgr,
	}
}

func Test_Template_ReadOnGetError(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGetDiagnosesError(mock.MatchedBy(StringPtrMatcher("InitialModelValue")), "unit-test-exception")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "unit-test-exception")
}

func Test_Template_ReadIMRU_ReadReturnsError(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenImmutableRUReturnsError("InitialModelValue", "ImmutableReadError")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "ImmutableReadError")
}

func Test_Template_ReadIMRU_ReadReturnsErrorWithoutDiagnostics(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenImmutableRUReturnsErrorWithoutDiagnostics("InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "Missing read error reason")
}

func Test_Template_ReadIMRU_ReadReturnsResourceNotFound(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenImmutableRUReturns("InitialModelValue", ResourceNotFound)
	testCtx.ResponseMock.ThenResourceIsRemoved()

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
}

func Test_Template_ReadIMRU_ReadReturnsResourceExists(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenImmutableRUReturns("InitialModelValue", ResourceExists)
	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("OkayModel", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
}

func Test_Template_ReadMURU_NothingHappensIfAlreadyDrifted(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.ResourceUnderTest.MutableRU = &MutableRUMock[string, core.ConfidentialStringData, string]{}
	testCtx.SpecializerMock.On("GetConfidentialMaterialFrom", "InitialModelValue").Return(
		ConfidentialMaterialModel{
			EncryptedSecret: types.StringValue(CreateDriftMessage("UNIT-TEST")),
		},
	)

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
}

func Test_Template_ReadMURU_IfCiphertextExpired(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenExpiredCiphertext(t, "InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "Ciphertext has expired")
}

func Test_Template_ReadMURU_IfCiphertextAlmostExpired(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenExpiringCiphertext(t, "InitialModelValue")
	testCtx.GivenMutableRUReturns("InitialModelValue", ResourceExists)
	testCtx.GivenObjectCanBePlacedAsRequested()

	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("OkayModel", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasWarning(t, "Ciphertext is about to expire")
}

func Test_Template_ReadMURU_IfCiphertextBeyondExpiry(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenCiphertextExpiringIn3Months(t, "InitialModelValue")
	testCtx.GivenMutableRUReturns("InitialModelValue", ResourceExists)
	testCtx.GivenObjectCanBePlacedAsRequested()

	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("OkayModel", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	assert.Equal(t, 0, len(*testCtx.ResponseMock.Diagnostic))
}

func Test_Template_ReadMURU_IfCiphertextCannotBePlaced(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenCiphertextExpiringIn3Months(t, "InitialModelValue")
	testCtx.GivenObjectCannotBePlacedAsRequested("NonPlaceableObject")
	//testCtx.GivenMutableRUReturns("InitialModelValue", ResourceExists)
	//testCtx.GivenJsonDataImporter()
	//
	//testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("OkayModel", "InitialModelValue", StringComparator)
	//testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "NonPlaceableObject")
}

func Test_Template_ReadMURU_IfResourceIsNotFound(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenCiphertextExpiringIn3Months(t, "InitialModelValue")
	testCtx.GivenObjectCanBePlacedAsRequested()
	testCtx.GivenMutableRUReturns("InitialModelValue", ResourceNotFound)
	//
	//testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("OkayModel", "InitialModelValue", StringComparator)
	//testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")
	testCtx.ResponseMock.ThenResourceIsRemoved()

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
}

func Test_Template_ReadMURU_IfResourceMatchesConfidentialData(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenCiphertextExpiringIn3Months(t, "InitialModelValue")
	testCtx.GivenObjectCanBePlacedAsRequested()
	testCtx.GivenMutableRUReturns("InitialModelValue", ResourceExists)

	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("OkayModel", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
}

func Test_Template_ReadMURU_IfResourceDriftsFromConfidentialData(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenCiphertextExpiringIn3Months(t, "InitialModelValue")
	testCtx.GivenObjectCanBePlacedAsRequested()
	testCtx.GivenMutableRUReturns("InitialModelValue", ResourceConfidentialDataDrift)

	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("OkayModel", "InitialModelValue", StringComparator)
	testCtx.MutableRU.ThenDriftWillBeSet("InitialModelValue", StringComparator)

	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.ResourceUnderTest.ReadT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
}

func Test_Template_Create_IfCiphertextExpired(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenExpiredCiphertext(t, "InitialModelValue")

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "Ciphertext has expired")
}

func Test_Template_Create_IfCiphertextCannotBePlaced(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenCiphertextExpiringIn3Months(t, "InitialModelValue")
	testCtx.GivenObjectCannotBePlacedAsRequested("NonPlaceableObject")

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "NonPlaceableObject")
}

func Test_Template_Create_UseLimitedCiphertextDeployedOverNonTrackingProvider(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 10)
	testCtx.GivenObjectCanBePlacedAsRequested()
	testCtx.FactoryMock.GivenObjectTrackingConfigured(false)

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "Insecure provider configuration")
}

func Test_Template_Create_UseLimitedCiphertextIfTrackingCheckFails(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 10)
	testCtx.GivenObjectCanBePlacedAsRequested()
	testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	testCtx.FactoryMock.GivenGetTackedObjectUsesErrs("unit-test-tracking-check")

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "Cannot assert the number of times this ciphertext was used")
}

func Test_Template_Create_UseLimitedCiphertextIfCreatesOverused(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 10)
	testCtx.GivenObjectCanBePlacedAsRequested()
	testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	testCtx.FactoryMock.GivenGetTackedObjectUses(10)

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "Ciphertext has been used all time it was allowed to do so")
}

func Test_Template_Create_AzObjectCreateErrs(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 10)
	testCtx.GivenObjectCanBePlacedAsRequested()
	testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	testCtx.FactoryMock.GivenGetTackedObjectUses(0)
	testCtx.SpecializerMock.GivenCreateErrs("InitialModelValue", "az-create-err")

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "az-create-err")
}

func Test_Template_Create_AzObjectCreatedWithUnlimitedTracking(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 0)
	testCtx.GivenObjectCanBePlacedAsRequested()
	// Note: these would not be checked if usage is unlimited.
	//testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	//testCtx.FactoryMock.GivenGetTackedObjectUses(0)
	testCtx.SpecializerMock.GivenCreate("InitialModelValue")

	// Then part
	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("CreatedAzureObject", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
}

func Test_Template_Create_AzObjectCreatedWithLimitedUseAndTrackingFails(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 10)
	testCtx.GivenObjectCanBePlacedAsRequested()

	testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	testCtx.FactoryMock.GivenGetTackedObjectUses(0)
	testCtx.SpecializerMock.GivenCreate("InitialModelValue")

	// Then part
	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("CreatedAzureObject", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.FactoryMock.GivenTrackObjectIdErrs()

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasError(t, "Incomplete object tracking")
}

func Test_Template_Create_AzObjectCreatedWithSingleUse(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 1)
	testCtx.GivenObjectCanBePlacedAsRequested()

	testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	testCtx.FactoryMock.GivenGetTackedObjectUses(0)
	testCtx.SpecializerMock.GivenCreate("InitialModelValue")

	// Then part
	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("CreatedAzureObject", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.FactoryMock.GivenTrackObject()

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
	testCtx.AssertResponseHasNoWarnings(t)
}

func Test_Template_Create_AzObjectCreatedWithUsageRemaining(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 10)
	testCtx.GivenObjectCanBePlacedAsRequested()

	testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	testCtx.FactoryMock.GivenGetTackedObjectUses(6)
	testCtx.SpecializerMock.GivenCreate("InitialModelValue")

	// Then part
	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("CreatedAzureObject", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.FactoryMock.GivenTrackObject()

	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
	testCtx.AssertResponseHasNoWarnings(t)
}

func Test_Template_Create_AzObjectCreatedWithWarningOnLastUse(t *testing.T) {
	testCtx := givenSetup()

	testCtx.RequestMock.GivenGet()
	testCtx.GivenUseLimitedCiphertext(t, "InitialModelValue", 2)
	testCtx.GivenObjectCanBePlacedAsRequested()

	testCtx.FactoryMock.GivenObjectTrackingConfigured(true)
	testCtx.FactoryMock.GivenGetTackedObjectUses(1)
	testCtx.SpecializerMock.GivenCreate("InitialModelValue")

	// Then part
	testCtx.SpecializerMock.ThenAzValueIsConvertedToTerraform("CreatedAzureObject", "InitialModelValue", StringComparator)
	testCtx.ResponseMock.ThenTerraformModelIsSet("InitialModelValue")

	testCtx.FactoryMock.GivenTrackObject()
	testCtx.ResourceUnderTest.CreateT(
		context.Background(),
		testCtx.RequestMock.AsRequestAbstraction(),
		testCtx.ResponseMock.AsResponseAbstraction())

	testCtx.AssertExpectations(t)
	testCtx.AssertResponseHasNoError(t)
	testCtx.AssertResponseHasWarning(t, "No more resource create are possible")
}
