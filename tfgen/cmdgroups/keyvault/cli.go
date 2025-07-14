package keyvault

type KeyVaultGroupCLIParams struct {
	inputFile       string
	inputIsBase64   bool
	vaultName       string
	vaultObjectName string
}

func (mdl *KeyVaultGroupCLIParams) SpecifiesVault() bool {
	return len(mdl.vaultName) > 0 && len(mdl.vaultObjectName) > 0
}
