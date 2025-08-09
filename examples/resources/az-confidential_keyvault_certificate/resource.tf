# ----------------------------------------------------------------------------
#
# Azure Key Vault Certificate
#
# The resource allows importing certificate into the key vault form the
# encrypted (cipher-text) version of certificate private key and associated
# certificate chain.
#
# The resource implement most attributes that `azurerm_key_vault_certificate`
# resource implements. This resource does not implement `resource_manager_id`
# and `resource_manager_versionless_id` attributes. Should the practitioner
# require obtaining these parameters, the use of `azurerm_key_vault_certificate`
# data source is recommended.
# ----------------------------------------------------------------------------

resource "az-confidential_keyvault_certificate" "cert" {
  content = <<-CIPHERTEXT
         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
         AP//75dWZg8VAAA=
         CIPHERTEXT

  # This certificate is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  # The certificate version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-08-09T14:29:29Z"

  # The certificate version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-08-09T14:29:29Z"

  tags = {
    # Fill the tags as desired
    # tagName =  "TagValue"
  }

  destination_certificate = {
    vault_name = "demo-vault"
    name       = "demo"
  }
}
