Creates a subscription with specified primary and secondary subscription
keys without revealing these  value in state.

This resource can be used e.g. in a situation where an Terraform practitioner
needs to manage a high number of periodically rotated subscription keys for 
multiple API consumers where (a) storing these keys in the Terraform code in the 
clear is not desired while (b) storing these keys in a Key Vault service
creates a maintenance overhead.

## How to create the ciphertext
The ciphertext (i.e. the value of the `content` attribute) can be created with the `encrypt_apim_subscription` function.
This function will generate only the ciphertext. A complimentary [`tfgen`](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen)
tool can used to generate both ciphertext
and the Terraform code template.

As a pre-requisite, you need to have a public key of the key-encryption key the action provider instance will
be using.

### Example how to create ciphertext using Terraform provider

Consider the following example that creates a ciphertext that can be used for test and acceptance purposes for
next year when the content should not be read more than 50 times:

```terraform
variable "primary_key" {
  type        = string
  description = "Primary subscription key value"
}
variable "secondary_key" {
  type        = string
  description = "Secondary subscription key value"
}

variable "public_key_file" {
  type        = string
  description = "Public key file"
}

locals {
  public_key = file(var.public_key_file)
}

output "encrypted_apim_subscription" {
  value = provider::az-confidential::encrypt_apim_subscription (
    {
      primary_key   = var.primary_key
      secondary_key = var.secondary_key
    },
    {
      # These parameters are typically known upfront and can be considered
      # long-lived or fixed. If desired, these values can also be expressed
      # as variables.
      az_subscription_id  = "123421"
      resource_group      = "rg"
      api_management_name = "apim"
      apim_subscription_id : "subscriptionId",
      api_id     = "",
      product_id = "productId"
      user_id    = "abc-def"
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

Please refer to the [`encrypt_apim_subscription` function documentation](../functions/encrypt_apim_subscription.md)
for the description of the parameters the function accepts.

### Create ciphertext using `tfgen` tool

The ciphertext as well as a complete Terraform datasource template can be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen).)
The prompt equivalent to the function invocation illustrated above is:
```shell
tfgen -pubkey [path to the public key] \
  -provider-constraints demo,acceptance \
  -num-uses 50 \
  apim subscription
```
The tool will prompt for the interactive content input. Further options can be obtained by `tfgen -help` and
`tfgen apim subscription -help` commands.

