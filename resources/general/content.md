Datasource unwrapping (potentially very long) content into state

This resource is an illustration of how to overcome the limitation of RSA encryption
which cannot, on its own, encrypt a very large file.

## How to create the ciphertext
The ciphertext (i.e. the value of the `content` attribute) can be created with the `encrypt_general_content` content.
This function will generate only the ciphertext. A complimentary [`tfgen`](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen) 
tool can used to generate both ciphertext
and the Terraform code template.

As a pre-requisite, you need to have a public key of the key-encryption key the action provider instance will
be using.

### Example how to create ciphertext using Terraform provider

Consider the following example that creates a ciphertext that can be used for test and acceptance purposes for 
next year when the content should not be read more that 50 times:

```terraform
variable "content" {
  type = string
  description = "Content that needs to be wrapped"
}

variable "public_key_file" {
  type = string
  description = "Public key file"
} 

locals {
  public_key = file(var.public_key_file)
}

output "encrypted_content" {
  value = provider::az-confidential::encrypt_general_content(
    var.content,
    {
      expires_after = 365
      num_uses = 50
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}

```

Please refer to the [`encrypt_general_content` function documentation](../functions/encrypt_general_content.md)
function documentation for the description of the parameters the function accepts.

### Create ciphertext using `tfgen` tool


The ciphertext as well as a complete Terraform datasource template can be obtained using the `tfgen` command-line tool
(see [source code](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential-tfgen).)
The prompt equivalent to the function invocation illustrated above is:
```shell
tfgen -pubkey [path to the public key] \
  -provider-constraints demo,acceptance \
  -num-uses 50 \
  general content
```
The tool will prompt for the interactive content input. Further options can be obtained by `tfgen -help` and
`tfgen general content -help` commands.