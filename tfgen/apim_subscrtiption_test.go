package tfgen

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	res_apim "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/apim"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
	"time"
)

func Test_Apim_Subscription_DefaultOptions(t *testing.T) {
	executeSubscriptionEncryptionCycle(t,
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

func Test_Apim_Subscription_Unprotected(t *testing.T) {
	executeSubscriptionEncryptionCycle(t,
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

func Test_Apim_Subscription_CustomTimingLimits(t *testing.T) {
	executeSubscriptionEncryptionCycle(t,
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

func Test_Apim_Subscription_CreateOnce(t *testing.T) {
	now := time.Now().Unix()

	executeSubscriptionEncryptionCycle(t,
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

func Test_Apim_Subscription_ProviderConstraints(t *testing.T) {
	expProviderLimits := []core.ProviderConstraint{
		"test", "acceptance",
	}
	executeSubscriptionEncryptionCycle(t,
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

func Test_Apim_Subscription_PlacementConstraint(t *testing.T) {
	expPlacement := []core.PlacementConstraint{
		"az-c-label:///subscriptions/az-subscription-id/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim/subscriptions/sid?api=/product=/user=",
	}

	executeSubscriptionEncryptionCycle(t,
		[]string{
			LockDestinationCliOption.Opt(),
		}, // no main tions
		[]string{
			apim.AzSubscriptionIdOptionCliOption.Opt(), "az-subscription-id",
			apim.ResourceGroupNameCliOption.Opt(), "rg",
			apim.ServiceNameCliOption.Opt(), "apim",
			apim.SubscriptionIdCliOption.Opt(), "sid",
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

func Test_Apim_Subscription_FullApiIdPlacementConstraint(t *testing.T) {
	expPlacement := []core.PlacementConstraint{
		"az-c-label:///subscriptions/az-subscription-id/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim/subscriptions/sid?api=apiId/product=/user=ownerId",
	}

	executeSubscriptionEncryptionCycle(t,
		[]string{
			LockDestinationCliOption.Opt(),
		}, // no main tions
		[]string{
			apim.AzSubscriptionIdOptionCliOption.Opt(), "az-subscription-id",
			apim.ResourceGroupNameCliOption.Opt(), "rg",
			apim.ServiceNameCliOption.Opt(), "apim",
			apim.SubscriptionIdCliOption.Opt(), "sid",
			apim.ApiIdCliOption.Opt(), "apiId",
			apim.OwnerIdCliOption.Opt(), "ownerId",
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

func Test_Apim_Subscription_FullProductIdPlacementConstraint(t *testing.T) {
	expPlacement := []core.PlacementConstraint{
		"az-c-label:///subscriptions/az-subscription-id/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim/subscriptions/sid?api=/product=productId/user=ownerId",
	}

	executeSubscriptionEncryptionCycle(t,
		[]string{
			LockDestinationCliOption.Opt(),
		}, // no main tions
		[]string{
			apim.AzSubscriptionIdOptionCliOption.Opt(), "az-subscription-id",
			apim.ResourceGroupNameCliOption.Opt(), "rg",
			apim.ServiceNameCliOption.Opt(), "apim",
			apim.SubscriptionIdCliOption.Opt(), "sid",
			apim.ProductIdCliOption.Opt(), "productId",
			apim.OwnerIdCliOption.Opt(), "ownerId",
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

func executeSubscriptionEncryptionCycle(t *testing.T, commonOptions, commandOptions []string, assertHeaderExpectations func(*testing.T, core.ConfidentialDataJsonHeader)) {
	decrypter, mock := givenSetup(t)

	mock.GivenReadRequestReturns(apim.SubscriptionPrimaryKeyPrompt, []byte("primaryKey"))
	mock.GivenReadRequestReturns(apim.SubscriptionSecondaryKeyPrompt, []byte("secondaryKey"))

	cmdLine := slices.Concat(commonOptions, []string{ApimGroup, apim.SubscriptionCommand}, commandOptions)

	_, _, em, err := MainEntryPointDispatch(mock.ReadInput, cmdLine...)
	assert.NoError(t, err)

	header, data, err := res_apim.DecryptSubscriptionMessage(em, decrypter)
	assert.NoError(t, err)
	assert.True(t, len(header.Uuid) > 5)
	assert.Equal(t, res_apim.SubscriptionObjectType, header.Type)

	assert.Equal(t, "primaryKey", data.GetPrimaryKey())
	assert.Equal(t, "secondaryKey", data.GetSecondaryKey())
	assertHeaderExpectations(t, header)
}
