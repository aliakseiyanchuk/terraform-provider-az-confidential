package tfgen

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"
	res_kv "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/keyvault"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
	"time"
)

func Test_KV_Key_DefaultOptions(t *testing.T) {
	executeKvKeyEncryptionCycle(t,
		[]string{}, // no main tions
		[]string{}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assertHoursInFuture(t, 72, header.CreateLimit)
			assertDaysInFuture(t, 365, header.Expiry)
			assert.Equal(t, 10, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func Test_KV_Key_Unprotected(t *testing.T) {
	executeKvKeyEncryptionCycle(t,
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

func Test_KV_Key_CustomTimingLimits(t *testing.T) {
	executeKvKeyEncryptionCycle(t,
		[]string{
			TimeToCreateCliOption.Opt(), "24h",
			DaysToExpireCliOption.Opt(), "20",
			NumberOfTimesUsesOption.Opt(), "5",
		},
		[]string{}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assertHoursInFuture(t, 24, header.CreateLimit)
			assertDaysInFuture(t, 20, header.Expiry)
			assert.Equal(t, 5, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func Test_KV_Key_CreateOnce(t *testing.T) {
	now := time.Now().Unix()

	executeKvKeyEncryptionCycle(t,
		[]string{CreateOnceOption.Opt()}, // no main tions
		[]string{},                       // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assert.True(t, header.CreateLimit > now)
			assert.True(t, header.Expiry > now)
			assert.Equal(t, 1, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.Equal(t, 0, len(header.PlacementConstraints))
		},
	)
}

func Test_KV_Key_ProviderConstraints(t *testing.T) {
	expProviderLimits := []core.ProviderConstraint{
		"test", "acceptance",
	}
	executeKvKeyEncryptionCycle(t,
		[]string{
			ProviderConstraintsCliOption.Opt(), "acceptance,test",
		}, // no main tions
		[]string{}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assertHoursInFuture(t, 72, header.CreateLimit)
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

func Test_KV_Key_PlacementConstraint(t *testing.T) {
	expPlacement := []core.PlacementConstraint{
		"az-c-keyvault://dest-vault@keys=dest-key",
	}
	executeKvKeyEncryptionCycle(t,
		[]string{
			LockDestinationCliOption.Opt(),
		}, // no main tions
		[]string{
			keyvault.DestinationVaultCliOption.Opt(), "dest-vault",
			keyvault.DestinationVaultKeyCliOption.Opt(), "dest-key",
		}, // op command options,

		func(t *testing.T, header core.ConfidentialDataJsonHeader) {
			assertHoursInFuture(t, 72, header.CreateLimit)
			assertDaysInFuture(t, 365, header.Expiry)
			assert.Equal(t, 10, header.NumUses)
			assert.Equal(t, 0, len(header.ProviderConstraints))
			assert.True(
				t,
				core.SameBag[core.PlacementConstraint](
					func(a, b core.PlacementConstraint) bool { return a == b },
					expPlacement,
					header.PlacementConstraints,
				),
			)
		},
	)
}

func executeKvKeyEncryptionCycle(t *testing.T, commonOptions, commandOptions []string, assertHeaderExpectations func(*testing.T, core.ConfidentialDataJsonHeader)) {
	decrypter, mock := givenSetup(t)

	mock.GivenReadRequestReturns(keyvault.PrivateKeyPrompt, testkeymaterial.EphemeralRsaKeyText)

	cmdLine := slices.Concat(commonOptions, []string{KeyVaultGroup, keyvault.KeyCommand}, commandOptions)

	_, _, em, err := MainEntryPointDispatch(mock.ReadInput, cmdLine...)
	assert.NoError(t, err)

	header, _, err := res_kv.DecryptKeyMessage(em, decrypter)
	assert.NoError(t, err)
	assert.True(t, len(header.Uuid) > 5)
	assert.Equal(t, res_kv.KeyObjectType, header.Type)

	//assert.Equal(t, "this is a secret content", data.Get())
	// TODO: we may want to assert that the returned key is the same.
	assertHeaderExpectations(t, header)
}
