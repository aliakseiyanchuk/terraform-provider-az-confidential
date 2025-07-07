package core

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_IsResourceNotFoundError(t *testing.T) {
	txt := "GET" +
		" https://lspwd2-d-confidential-kv.vault.azure.net/secrets/example-secret-3a/b3b6937782b840989d248ce90f71c709" +
		" --------------------------------------------------------------------------------\n" +
		"RESPONSE 404: 404 Not Found\n" +
		" ERROR CODE: SecretNotFound\n" +
		" --------------------------------------------------------------------------------\n│" +
		"{\n" +
		"   \"error\": {\n" +
		"     \"code\": \"SecretNotFound\",\n" +
		"     \"message\": \"A secret with (name/id) example-secret-3a/b3b6937782b840989d248ce90f71c709 was not found in this key vault. If you recently deleted this secret you may be able to recover it using the correct recovery command. For help resolving this issue, please see https://go.microsoft.com/fwlink/?linkid=2125182\"\n" +
		"   }\n" +
		" }\n" +
		" --------------------------------------------------------------------------------"

	assert.True(t, IsResourceNotFoundError(errors.New(txt)))
	assert.False(t, IsResourceNotFoundError(fmt.Errorf("is is not an expected message")))
}
