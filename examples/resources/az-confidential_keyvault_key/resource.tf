# ----------------------------------------------------------------------------
#
# Azure Key Vault Key
#
# The resource allows importing RSA and EC keys into the key vault form the
# encrypted (cipher-text) version of private key material.
# ----------------------------------------------------------------------------

resource "az-confidential_keyvault_key" "key" {
  content = <<-CIPHERTEXT
         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
         CIPHERTEXT

  # This key is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true
  key_opts = toset([
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "wrapKey",
    "unwrapKey",
  ])

  # The key version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-08-09T14:56:43Z"

  # The key version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-08-09T14:56:43Z"

  tags = {
    # Fill the tags as desired
    # tagName =  "TagValue"
  }

  destination_key = {
    vault_name = "demo-vault"
    name       = "demo"
  }
}