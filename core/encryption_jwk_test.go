package core

import (
	"encoding/json"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"testing"
)
import "github.com/aliakseiyanchuk/terraform-provider-az-confidential/core/testkeymaterial"

func TestPrivateKeyMarshallingToJWK(t *testing.T) {
	blocks, err := ParsePEMBlocks(testkeymaterial.EphemeralRsaKeyText)
	assert.Nil(t, err)

	pemBlock := FindPrivateKeyBlock(blocks)
	rsaKey, rsaLoadErr := PrivateKeyFromBlock(pemBlock)
	assert.Nil(t, rsaLoadErr)

	jwkKey, jwkImportErr := jwk.Import(rsaKey)
	assert.Nil(t, jwkImportErr)

	jwkKeyJson, jsonErr := json.Marshal(&jwkKey)
	assert.Nil(t, jsonErr)

	print(string(jwkKeyJson))

	jwksSet, jwkSetParseError := jwk.Parse(jwkKeyJson)
	assert.Nil(t, jwkSetParseError)

	outputKey := azkeys.JSONWebKey{}
	err = ConvertJWKSToAzJWK(jwksSet, &outputKey)

	assert.Nil(t, err)
	assert.Equal(t, azkeys.KeyTypeRSA, *outputKey.Kty)
}
