package acceptance

import "github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"

type BaseEncryptFunctionParameters struct {
	PublicKey           string
	CreateLimit         string
	ExpiresIn           int
	NumUses             int
	ProviderConstraints []core.ProviderConstraint
}
