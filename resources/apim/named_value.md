Creates a named value in API Management without revealing its value in state.

This resource fills in a gap where a named value is sensitive enough to be avoided being stored
in the Terraform configuration in the clear yet not sensitive enough to be placed in the key vault.

An example of such a scenario is a shared code repository containing routing configuration
belonging to different teams. The purpose of adding this protection here would be to allow the
teams to collaborate without exposing routing internals. Adopting this resource can help avoiding
a churn of secrets in Key Vault.

## How to create the ciphertext
The ciphertext (i.e. the value of the `content` attribute) can be created with the `encrypt_apim_named_value` function.
This function will generate only the ciphertext. A complimentary [`tfgen`](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen)
tool can used to generate both ciphertext
and the Terraform code template.

As a pre-requisite, you need to have a public key of the key-encryption key the action provider instance will
be using.

### Example how to create ciphertext using Terraform provider

Consider the following example that creates a ciphertext that can be used for test and acceptance purposes for
next year when the content should not be read more than 50 times:

```terraform
variable "content" {
  type        = string
  description = "Named value to be wraoped"
}

variable "public_key_file" {
  type        = string
  description = "Public key file"
}

locals {
  public_key = file(var.public_key_file)
}

output "encrypted_named_value" {
  value = provider::az-confidential::encrypt_apim_named_value(
    var.content,
    {
      az_subscription_id  = "123421"
      resource_group      = "rg"
      api_management_name = "apim"
      name : "namedValue123",
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

Please refer to the [`encrypt_apim_named_value` function documentation](../functions/encrypt_apim_named_value.md)
for the description of the parameters the function accepts.

### Create ciphertext using `tfgen` tool

The ciphertext as well as a complete Terraform datasource template can be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen).)
The prompt equivalent to the function invocation illustrated above is:
```shell
tfgen -pubkey [path to the public key] \
  -provider-constraints demo,acceptance \
  -num-uses 50 \
  apim named_value
```
The tool will prompt for the interactive content input. Further options can be obtained by `tfgen -help` and
`tfgen apim named_value -help` commands.

