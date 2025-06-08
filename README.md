# Confidential Azure KeyVault Secrets Terraform Provider

## The problem this provider solves
This provider solves a problem of securely packaging confidential material (such OAuth key secrets, API keys,
encryption/signing keys, etc.) together with the application deployments without compromising confidentiality of the
overall deployment.

Standard Azure KeyVault Terraform resources [azurerm_key_vault_key](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key),
do not provide means of importing keys into key vault. This is understandable as unencrypted version of the private
key would need to available in the source code! [Importing X509 certificates](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_certificate)
does offer protection if importing from a password-protected PFX file; however the password needs to be 
in the configuration. [Secret](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret)
do need to be specified in the Terraform source code by value.

Yet there are scenarios -- e.g. in the context of building DevOps platform operations -- where a feature team
may need package specific cryptographic material alongside with the application code. To give example: a feature team is collaborating
with a third-party vendor which requires signing API requests with the specific, vendor-issued RSA key. 

It is possible to arrange a transmissions of key materials from a feature team into platform's security storage. 
However, this practice can quickly turn into a taxing, error-prone operation as the number of feature teams requiring
the use of specific secrets and keys increases. 

This provider allows the DevOps platform operations to empower the feature team to securely package specific key 
material as Terraform source code without compromising the integrity of the confidential material, ultimately allowing 
achieving DevOps self-service experience to the feature teams.

## How it works

