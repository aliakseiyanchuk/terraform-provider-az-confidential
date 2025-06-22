---
page_title: "Terraform code generator CLI"
---

# Terraform Code Generator

The encrypted content for this provider should be produced with the
supplied `tfgen` tool that performs packaging and encryption of the  
confidential material into the Terraform code.

## General Syntax

The command line syntax is as follows:
`tfgen [common options] [subcommand] [subcommand options]`

Common options:
- `-output-vault` specifies the Azure Key Vault name where unpacked object needs to be stored
- `-output-vault-object` the object name (key, secret, or certificate) to be unpacked into
- `-wrapping-key-vault` the vault containing the KEK
- `-wrapping-key-name` the name of KEK
- `-wrapping-key-version` the version of KEK used (in case it's not latest)
- `-pubkey` public key of the KEK
- `-no-labels`: do not add any labels to the encrypted ciphertext
- `-fixed-labels`: add the specified list of labels to the ciphertext
- `-target-only-label`: associate a single label with the ciphertext that is based on
   the values supplied in `output-vault` and `output-vault-object` options.
- `-ciphertext-only` output only ciphertext; don't generate Terraform template

## Sub-commands:
- `password`: generates a password that **will be** in the state file. This datasource
   is added to support the feature of providing very long passwords (i.e. those that cannot
   be encrypted by an RSA key alone)
- `secret`: encrypt a secret
- `key`: encrypt an RSA, EC, or a symmetric key
- `certificate` encrypt a certificate

## Encrypting Password

The command synopsis is:
`tfgen [common options] password [password options]`

Command options are:
- `-password-file`: read the password for a specified file
- `-base64`: the file (or input) being read is base-64 encoded

Where the password file would not be specified, the program will attempt to read input from the standard input.
If not available, interactive prompt will be used to prompt to enter the password information.

Example to label the password to with provides configured to accept the `demo` and `testing` labels:
```shell
tfgen -pubkey PATH_TO_PUB_KEY -fixed-labels demo,testing password
```

A successful execution of this command should produce a template that looks as follows:
```terraform
#
# Minimal terraform code for your example:
# ----------------------------------------------------------------------------

data "az-confidential_password" "confidential_password" {
  content = "....a very long, base-64 encoded ciphertext ciphertext..."
}
```
## Encrypt secret

The command synopsis is:
`tfgen [common options] secret [secret options]`

Command options are:
- `-secret-file`: read the secret for a specified file
- `-base64`: the file (or input) being read is base-64 encoded

Where the secret would not be specified, the program will attempt to read input from the standard input.
If not available, interactive prompt will be used to prompt to enter the password information.

Example to label the secret to be used with a provider configured to accept the `demo` and `testing` labels:
```shell
tfgen -pubkey PATH_TO_PUB_KEY \
  -output-vault demo-vault -output-vault-object demo \
  -fixed-labels demo,testing \
  secret
```
A successful execution of this command should produce a template that looks as follows:
```terraform
#
# Minimal terraform code for your example:
# ----------------------------------------------------------------------------

resource "az-confidential_secret" "secret" {
  content = "...a very long, base-64 encoded ciphertext ciphertext..."

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  # The secret version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-06-21T18:04:00Z"

  # The secret version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-06-21T18:04:00Z"

  tags = {
    # Fill the tags as desired
    # tagName =  "TagValue"
  }

  destination_secret = {
    vault_name = "demo-vault"
    name = "demo"
  }
}
```
> You may need to modify this template as required for your project.

## Encrypt a key

The command synopsis is:
`tfgen [common options] key [secret options]`

Command options are:
- `-key-file`: read the secret for a specified file
- `-password-file`: read the password for the encrypted private key from the specified file
- `-base64`: the file (or input) being read is base-64 encoded
- `-symmetric` The key being created is a symmetric key

Where the key would not be specified, the program will attempt to read input from the standard input.
If not available, interactive prompt will be used to prompt to enter the password information.
The same logic applied for passwords.

Example to label the key to be used with a provider configured to accept the `demo` and `testing` labels:
```shell
tfgen -pubkey PATH_TO_PUB_KEY \
  -output-vault demo-vault -output-vault-object demo \
  -fixed-labels demo,testing \
  key
```
A successful execution of this command should produce a template that looks as follows:
```terraform
#
# Minimal terraform code for your example:
# ----------------------------------------------------------------------------

resource "az-confidential_key" "key" {
  content = "...a very long, base-64 encoded ciphertext ciphertext..."

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  key_opts = toset([
    "decrypt",
    "encrypt",
    "import",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey"
  ])

  # The secret version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-06-21T18:10:21Z"

  # The secret version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-06-21T18:10:21Z"

  tags = {
        # Fill the tags as desired
        # tagName =  "TagValue"
      }

  destination_key = {
        vault_name = "demo-vault"
        name = "demo"
  }
}
```
> You may need to tweak the parameters of the allowed key operations as required to your use case.

## Encrypt a certificate

The command synopsis is:
`tfgen [common options] certificate [secret options]`

Command options are:
- `-cert-file`: read the secret for a specified file
- `-password-file`: read the password for the encrypted private key from the specified file
- `-base64`: the file (or input) being read is base-64 encoded
- `-no-der-verify` Skip verification of DER-encoded certificate

Where the key would not be specified, the program will attempt to read input from the standard input.
If not available, interactive prompt will be used to prompt to enter the password information.
The same logic applied for passwords.

Example to label the certificate to be used with a provider configured to accept the `demo` and `testing` labels:
```shell
tfgen -pubkey PATH_TO_PUB_KEY \
  -output-vault demo-vault -output-vault-object demo \
  -fixed-labels demo,testing \
  key
```
A successful execution of this command should produce a template that looks as follows:
```terraform
#
# Minimal terraform code for your example:
# ----------------------------------------------------------------------------

resource "az-confidential_key" "key" {
  content = "...a very long, base-64 encoded ciphertext ciphertext..."

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  key_opts = toset([
    "decrypt",
    "encrypt",
    "import",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey"
  ])

  # The secret version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-06-21T18:10:21Z"

  # The secret version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-06-21T18:10:21Z"

  tags = {
        # Fill the tags as desired
        # tagName =  "TagValue"
      }

  destination_key = {
        vault_name = "demo-vault"
        name = "demo"
  }
}
```
> You may need to tweak the parameters of the allowed key operations as required to your use case.