terraform {
  required_providers {
    az-confidential = {
      source = "hashicorp.com/lspwd2/az-confidential"
    }
  }
}

provider "az-confidential" {
  tenant_id       = var.az_tenant_id
  subscription_id = var.az_subscription_id
  client_id       = var.az_client_id
  client_secret   = var.az_client_secret

  oaep_label = "ZGVtbw=="

  default_wrapping_key = {
    vault_name = var.az_default_vault_name
    name       = var.az_default_wrapping_key
    version    = var.az_default_wrapping_key_version
  }

  default_destination_vault_name = var.az_default_vault_name
}

