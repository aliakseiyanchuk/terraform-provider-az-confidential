package keyvault

import "github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"

const (
	DestinationVaultCliOption            model.CLIOption = "destination-vault"
	DestinationVaultSecretCliOption      model.CLIOption = "destination-secret-name"
	DestinationVaultKeyCliOption         model.CLIOption = "destination-key-name"
	DestinationVaultCertificateCliOption model.CLIOption = "destination-cert-name"
)

const (
	SecretContentPrompt = "Enter secret data"

	PrivateKeyPrompt         = "Enter key data (hit Enter twice to end input)"
	PrivateKeyPasswordPrompt = "Private key requires password"

	CertificateDataPrompt     = "Enter certificate data (hit Enter twice to end input)"
	CertificatePasswordPrompt = "This certificate is password protected; kindly supply it"
)

const (
	SecretCommand      = "secret"
	KeyCommand         = "key"
	CertificateCommand = "certificate"
)
