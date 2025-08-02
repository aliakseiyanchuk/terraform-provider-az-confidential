package tfgen

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	res_general "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/general"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
)

func Test_General_Content_DefaultOptions(t *testing.T) {
	executeGeneralContentEncryptionCycle(t,
		[]string{}, // no main tions
		[]string{}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assert.Equal(t, int64(0), header.CreateLimit)
			assertDaysInFuture(t, 365, header.Expiry)
			assert.Equal(t, 10, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func Test_General_Content_Unprotected(t *testing.T) {
	executeGeneralContentEncryptionCycle(t,
		[]string{
			NoCreateLimitCliOption.Opt(),
			NoUsageLimitOption.Opt(),
			NoExpiryLimitCliOption.Opt(),
		},
		[]string{}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assert.Equal(t, int64(0), header.CreateLimit)
			assert.Equal(t, int64(0), header.Expiry)
			assert.Equal(t, -1, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func Test_General_Content_CustomTimingLimits(t *testing.T) {
	executeGeneralContentEncryptionCycle(t,
		[]string{
			DaysToExpireCliOption.Opt(), "20",
			NumberOfTimesUsesOption.Opt(), "5",
		},
		[]string{}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assert.Equal(t, int64(0), header.CreateLimit)
			assertDaysInFuture(t, 20, header.Expiry)
			assert.Equal(t, 5, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func Test_General_Content_CreateOnce(t *testing.T) {
	executeGeneralContentEncryptionCycle(t,
		[]string{CreateOnceOption.Opt()}, // no main tions
		[]string{},                       // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assert.Equal(t, int64(0), header.CreateLimit)
			assertDaysInFuture(t, 365, header.Expiry)
			assert.Equal(t, 1, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func Test_General_Content_ProviderConstraints(t *testing.T) {
	expProviderLimits := []core.ProviderConstraint{
		"test", "acceptance",
	}
	executeGeneralContentEncryptionCycle(t,
		[]string{
			ProviderConstraintsCliOption.Opt(), "acceptance,test",
		}, // no main tions
		[]string{}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assert.Equal(t, int64(0), header.CreateLimit)
			assertDaysInFuture(t, 365, header.Expiry)
			assert.Equal(t, 10, header.NumUses)
			assert.True(
				t,
				core.SameBag[core.ProviderConstraint](
					func(a, b core.ProviderConstraint) bool { return a == b },
					expProviderLimits,
					header.ProviderConstraints,
				),
			)
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func executeGeneralContentEncryptionCycle(t *testing.T, commonOptions, commandOptions []string, assertHeaderExpectations func(*testing.T, core.ConfidentialDataJsonHeader)) {
	decrypter, mock := givenSetup(t)

	mock.GivenReadRequestReturns(general.ContentPrompt, []byte("this is a secret content"))

	cmdLine := slices.Concat(commonOptions, []string{GeneralGroup, general.ContentCommand}, commandOptions)

	_, _, em, err := MainEntryPointDispatch(mock.ReadInput, cmdLine...)
	assert.NoError(t, err)

	header, data, err := res_general.DecryptContentMessage(em, decrypter)
	assert.NoError(t, err)
	assert.True(t, len(header.Uuid) > 5)
	assert.Equal(t, res_general.ContentObjectType, header.Type)

	assert.Equal(t, "this is a secret content", data.GetStingData())
	assertHeaderExpectations(t, header)
}
