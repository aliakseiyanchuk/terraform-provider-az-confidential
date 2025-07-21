package model

//func Test_KWP_GetLabels_WithStrictTargeting(t *testing.T) {
//	kwp := &ContentWrappingParams{
//		TargetCoordinateLabel: true,
//		DestinationCoordinate: AzKeyVaultObjectCoordinateTFCode{
//			AzKeyVaultObjectCoordinate: core.AzKeyVaultObjectCoordinate{
//				VaultName: "vault",
//				Name:      "secret",
//				Type:      "abc",
//			},
//		},
//	}
//
//	assert.Equal(t, 1, len(kwp.GetProviderConstraints()))
//	assert.Equal(t, kwp.DestinationCoordinate.GetLabel(), kwp.GetProviderConstraints()[0])
//}
//
//func Test_KWP_GetLabels_WithNoData(t *testing.T) {
//	kwp := &ContentWrappingParams{
//		TargetCoordinateLabel: false,
//		ProviderConstraints:                "",
//	}
//
//	assert.Equal(t, 0, len(kwp.GetProviderConstraints()))
//}
//
//func Test_KWP_GetLabels_WithData(t *testing.T) {
//	kwp := &ContentWrappingParams{
//		TargetCoordinateLabel: false,
//		ProviderConstraints:                "l1,l2,l3",
//	}
//
//	assert.Equal(t, 3, len(kwp.GetProviderConstraints()))
//	assert.Equal(t, "l1", kwp.GetProviderConstraints()[0])
//	assert.Equal(t, "l2", kwp.GetProviderConstraints()[1])
//	assert.Equal(t, "l3", kwp.GetProviderConstraints()[2])
//}
//
//func Test_KWP_ValidateDestination(t *testing.T) {
//	kwp := ContentWrappingParams{
//		DestinationCoordinate: AzKeyVaultObjectCoordinateTFCode{},
//	}
//
//	err := kwp.ValidateHasDestination()
//	assert.NotNil(t, err)
//	assert.Equal(t, "destination key name is required; use -output-vault-secret option", err.Error())
//
//	kwp.DestinationCoordinate.Name = "secret"
//	err = kwp.ValidateHasDestination()
//	assert.NotNil(t, err)
//	assert.Equal(t, "destination vault name is required; use -output-vault option", err.Error())
//
//	kwp.DestinationCoordinate.VaultName = "vault"
//	assert.Nil(t, kwp.ValidateHasDestination())
//}
