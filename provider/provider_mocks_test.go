package provider

import "github.com/stretchr/testify/mock"

type VersionedConfidentialDataMock struct {
	mock.Mock
}

func (v *VersionedConfidentialDataMock) GetUUID() string {
	args := v.Called()
	return args.Get(0).(string)
}

func (v *VersionedConfidentialDataMock) GetType() string {
	args := v.Called()
	return args.Get(0).(string)
}

func (v *VersionedConfidentialDataMock) GetLabels() []string {
	return v.Called().Get(0).([]string)
}

func (v *VersionedConfidentialDataMock) GivenUUID(uuid string) {
	v.On("GetUUID").Return(uuid)
}

func (v *VersionedConfidentialDataMock) GivenType(strType string) {
	v.On("GetType").Return(strType)
}

func (v *VersionedConfidentialDataMock) GivenLabels(labels []string) {
	v.On("GetLabels").Return(labels)
}
