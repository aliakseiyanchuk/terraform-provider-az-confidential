// Copyright (c) HashiCorp, Inc.

package resources

import (
	"encoding/base64"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/stretchr/testify/assert"
	"testing"
)

func mustDecodeBase64(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err != nil {
		panic(err)
	} else {
		return b
	}
}

func Test_CKMdl_AcceptECKey(t *testing.T) {
	keyID := to.Ptr("https://unit-test-fictitious-vault-name.vault.azure.net/keys/importedkeyv1/88ac1c5c71df4c169ab70d3ded5192f4")
	key := azkeys.JSONWebKey{
		Crv: to.Ptr(azkeys.CurveNameP256),
		KID: (*azkeys.ID)(keyID),
		Kty: to.Ptr(azkeys.KeyTypeEC),
		X:   mustDecodeBase64("AQX6InFKrBSdHa+rr9sMgLOUZYSKyVDNrdJn0BypmyI="),
		Y:   mustDecodeBase64("hDe5IvSt+40KnjAOTlXYCsd16blXtqLVWASQBRjbJEA="),
	}

	keyBundle := azkeys.KeyBundle{
		Key: &key,
		Attributes: &azkeys.KeyAttributes{
			Enabled: to.Ptr(true),
		},
	}

	dg := diag.Diagnostics{}

	ccm := ConfidentialKeyModel{}
	ccm.Accept(keyBundle, &dg)

	assert.False(t, dg.HasError())
	assert.False(t, ccm.PublicKeyPem.IsNull())
}

func Test_CKMdl_AcceptRsaKey(t *testing.T) {
	keyID := to.Ptr("https://unit-test-fictitious-vault-name.vault.azure.net/keys/importedkeyv1/88ac1c5c71df4c169ab70d3ded5192f4")
	key := azkeys.JSONWebKey{
		KID: (*azkeys.ID)(keyID),
		E:   mustDecodeBase64("AQAB"),
		Kty: to.Ptr(azkeys.KeyTypeRSA),
		N:   mustDecodeBase64("x6PaXN8G5yqJc06mB+HtzcHEvg5CXE8K2MgIqLjGGoOJJrxvdyj4ahxn434VVEFwlN0IDRvw4nsZwNOmXtQHqNYUHFJTfPVgbywjRPc72/v/81KVaMEDyLBgLKBndcAROYi2HTgp7DtllZGLCOFDMH0SwuAlJ/jM/O4YUksWyQRzVaEXYFoZvU48wKUp691Pp30xgAfaDKmXKXk/gJP+WqmaCEHLU26xxflOn0Jh50plClxfE5VNygeWNX2qfcHoeuV4AVktUhYMXXbaZar7cofVVg/Xb9RIDQtVtFEOBiOKLrDuFKmiJIcQm+SVPxVm32SwSaSJ32Mo68xc0VRZlwWZsU88mgfB0irQGigf1uSgbeyyhP1LqwO9Ko2axz4we86rr87MdV6fXwyLzofDUroQkCpX97h6kRpt2Oo+6a6dVMB0i1o39e0+s/x30DyF/NmYfp6OZeZ9ESexNK+Irs7AON0qsktMvJrZrwtWJc3dpR62/QOdYsn6Gg3Awz5/mVJmUXUeTlSNUwLXvRcg6+0R7h1I9QSsMp2rBrReJic3xzeU48v1Nsx8bThdHhHniJxbQKHLLPTkFPvU1GVQ/4+V/CknT5iV3y+hgcLK+RA013P7ZjYApzpVkMfBcUZbKzKOTb++nXzlJrWwCc2bkHaPtEkvXVnamkL9RoClPnk="),
	}

	keyBundle := azkeys.KeyBundle{
		Key: &key,
		Attributes: &azkeys.KeyAttributes{
			Enabled: to.Ptr(true),
		},
	}

	dg := diag.Diagnostics{}

	ccm := ConfidentialKeyModel{}
	ccm.Accept(keyBundle, &dg)

	assert.False(t, dg.HasError())
	assert.False(t, ccm.PublicKeyPem.IsNull())
}
