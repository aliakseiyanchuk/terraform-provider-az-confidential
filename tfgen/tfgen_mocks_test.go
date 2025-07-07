package tfgen

import (
	"errors"
	"github.com/stretchr/testify/mock"
)

type InputReaderMock struct {
	mock.Mock
}

func (m *InputReaderMock) GivenReadRequestReturnsString(prompt string, s string) {
	m.GivenReadRequestReturns(prompt, []byte(s))
}

func (m *InputReaderMock) GivenReadRequestReturns(prompt string, data []byte) {
	m.On("ReadInput", prompt, mock.Anything, mock.Anything, mock.Anything).
		Return(data, nil)
}

func (m *InputReaderMock) GivenReadRequestErrs(prompt string, errorMessage string) {
	m.On("ReadInput", prompt, mock.Anything, mock.Anything, mock.Anything).
		Return([]byte{}, errors.New(errorMessage))
}

func (m *InputReaderMock) ReadInput(prompt, fn string, base64Decode bool, multiline bool) ([]byte, error) {
	args := m.Called(prompt, fn, base64Decode, multiline)
	return args.Get(0).([]byte), args.Error(1)
}
