Creates a version of a key in the destination key vault from the
provided ciphertext and additional parameters supplied as
resource attributes.

The resource can import RSA or Elliptic curve.

# How to create the ciphertext
The ciphertext (i.e. the value of the `content` attribute) can be created with the `encrypt_keyvault_key` function.
This function will generate only the ciphertext. A complimentary [`tfgen`](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen)
tool can used to generate both ciphertext
and the Terraform code template.

As a pre-requisite, you need to have a public key of the key-encryption key the action provider instance will
be using.

### Example how to create ciphertext using Terraform provider

Consider the following example that creates a ciphertext that can be used for test and acceptance purposes for
next year when the content should not be read more than 50 times:

```terraform
variable "key_file" {
  type        = string
  description = "Private key file"
}

variable "password" {
  type        = string
  description = "Password for the key; empty string if not required"
}

locals {
  public_key = file(var.public_key_file)
  key_data = filebase64(var.cert_file)
}

output "encrypted_keyvault_key" {
  value = provider::az-confidential::encrypt_keyvault_key(
    {
      key      = local.key_data,
      password = var.password,
    },
    {
      vault_name = "vaultname123",
      name       = "keyName123",
    },
    {
      create_limit  = "72h"
      expires_after = 365
      num_uses      = 50
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}

```

Please refer to the [`encrypt_keyvault_key` function documentation](../functions/encrypt_keyvault_key.md)
for the description of the parameters the function accepts.

### Create ciphertext using `tfgen` tool

The ciphertext as well as a complete Terraform datasource template can be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen).)
The prompt equivalent to the function invocation illustrated above is:
```shell
tfgen -pubkey [path to the public key] \
  -provider-constraints demo,acceptance \
  -num-uses 50 \
  keyvault key
```
The tool will prompt for the interactive content input. Further options can be obtained by `tfgen -help` and
`tfgen keyvault key -help` commands.

