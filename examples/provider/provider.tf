
provider "az-confidential" {
  # Configure explicit client credentials
  tenant_id       = var.az_tenant_id
  subscription_id = var.az_subscription_id
  client_id       = var.az_client_id
  client_secret   = var.az_client_secret

  # Ensure that the provider will only unwrap the confidential objects
  # that are intended for this provider.
  labels              = ["test", "demo", "experimentation"]
  require_label_match = "provider-labels"

  default_wrapping_key = {
    vault_name = var.az_default_vault_name
    name       = var.az_default_wrapping_key
    version    = var.az_default_wrapping_key_version
  }

  # Track the objects created in storage account to make sure that
  # all confidential objects are unwrapped exactly once across all of your
  # intended installation.
  storage_account_tracker = {
    account_name   = var.az_storage_account_name
    table_name     = var.az_storage_account_table_name
    partition_name = var.az_storage_account_table_partition
  }

  default_destination_vault_name = var.az_default_vault_name
}

