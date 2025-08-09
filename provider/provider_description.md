Azure Confidential provider automates importing sensitive secrets, keys, and certificates from Terraform 
code into Azure services. To achieve the confidentiality, the sensitive materials are encrypted using RSA/AES encryption.
Furthermore, the provider never logs or stores the plain text in state.

A pre-requisite to using this provider is allocating a key vault containing a master RSA key (termed key-encryption key, or KEK) 
which  **must be adequately protected**. [This guide](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential/blob/main/docs-templates/guides/setup.md)
offers a starting point how this can be achieved.
> The confidentiality of the encrypted data depends primarily on the tightness of controls to use decrypt the
> ciphertext using the designated key-encryption key. It is important to ensure that all necessary controls are 
> implemented during the initial implementation. Additionally, the practitioner may want to set up additional 
> alerts concerning unexpected actions (such as permission changes) to detect malfeasance or breaches.

## Authenticating Provider

The preferred way of authenticating the provider is to set up the environment compatible with the
`azidentity.NewDefaultAzureCredential` requirements. (You can read about this e.g. [here](https://learn.microsoft.com/en-us/azure/developer/go/sdk/authentication/authentication-overview).)

For local development, the provider supports client credentials authentication that needs to be
provided to the provider e.g. via variables. 
To get started with testing this provider, the following configuration could be added to your project:
```terraform
provider "az-confidential" {
  tenant_id       = var.az_tenant_id
  subscription_id = var.az_subscription_id
  client_id       = var.az_client_id
  client_secret   = var.az_client_secret

  constraints         = ["demo", "test", "examples"]
  require_label_match = "provider-labels"

  default_destination_vault_name = var.az_default_vault_name

  default_wrapping_key = {
    vault_name = var.az_default_vault_name
    name       = var.az_default_wrapping_key
    version    = var.az_default_wrapping_key_version
  }
}

```

The required variables can be declared as follows:
```terraform
variable "az_tenant_id" {
  type = string
}

variable "az_subscription_id" {
  type = string
}

variable "az_client_id" {
  type = string
}

variable "az_client_secret" {
  type = string
}

variable "az_default_vault_name" {
  type = string
}

variable "az_default_wrapping_key" {
  type = string
}

variable "az_default_wrapping_key_version" {
  type = string
}
```

## Primary Protection
The ciphertext of the resources is protected by RSA cryptography. Only the people and processes granted the
decrypt permission on the key-encryption key (KEK). It is a recommended practice to rotate KEK at periodic intervals
and disable historic versions.
> Teh confidentiality of encrypted data is only as good as the controls around the KEK usage. Any person or process
> that technically is allowed to execute decrypt operation using this key would be able to decrypt and read
> the plain-text confidential data.

## Secondary Protection Measure
In addition to tightening the access to KEK and rotating it periodically, the provider 
implements complimentary mechanism that prevent accidental cross-environment copying, intentional duplication 
and misuse. Where any secondary protection embedded into the ciphertext will no longer be satisfied,
the Terraform plan/apply cycle will break. The Terraform practitioner is expected
to obtain a re-encrypted ciphertext or delete the concerned Azure resource.

### Provider Constraints
Provide constraints is a set of string labels is associated with a given provider instance in the Terraform project.
An author of the ciphertext has an option to specify the labels they expect the provider should be configured
with at the moment an encrypted message is created. 

A practical application of this technique is to guard against accidental copying of encrypted ciphertexts across
projects intended for different regions and environments.

### Ciphertext Usage Tracking
Ciphertext tracking is a feature which, as its name implies, tracks the use of the ciphertexts and allows each 
ciphertext to be unpacked the number of times the ciphertext author has allowed. I.e. if a resource is deleted and then 
added again, the second deployment
could be rejected if the parameters embedded in the ciphertext prohibit this. Internally, this feature is based on 
UUID identifier that is cryptographically added to the ciphertext when it is created.

The provider supports Azure Storage Account-base tracking which should be configured to track all ciphertext usages. 
This requires:
- creating a storage account (or designate any existing storage account);
- creating a table within that storage account;
- grant `Storage Table Data Contributor` role to the IAM account used by the provider.

The configuration required for this could look e.g. as follows:
```hcl
provider "az-confidential" {
  # ... other configuration properties

  storage_account_tracker = {
    account_name = ".. an account name"
    table_name = ".. a table name"
    partition_name = ".. a partition name"
  }
}
```

### Create time limiting
It is recommended to add a limit the "shelf life" of a ciphertext before an Azure object is created using the 
confidential material the ciphertext carries. Typically, such window would be rather short, several hours or several
days -- depending on the typical timeline between creating the ciphertext and initial deployment.

### Ciphertext expiry
Next to limiting the creat time, a ciphertext can embed the requirement for the confidential material owner to re-encrypt
the ciphertext periodically. This measure may be needed in certain context to ensure that the Terraform practitioner
is actually in possession of the original confidential material. (In that respect, it is similar to re-authenticating an active user
session periodically regardless of whether the user is still active.)

As a best practice recommendation, a ciphertext should be re-encrypted at least yearly.

### Number of permitted usages
The ciphertext can additionally constrain the number of times the ciphertext can be used, i.e. the number of times
an Azure object could be created using the encrypted confidential material. This measure allows the ciphertext author
to designate e.g. production object to be used once. 

When used in combination with create time limiting, this adds a secondary level of protection against accidental or
deliberate copying.

## Reporting issues or requesting new features

Please report issues or requests for new features on the [Github project](https://github.com/aliakseiyanchuk/terraform-provider-az-confidential/issues).