# Copyright (c) HashiCorp, Inc.

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

variable "az_apim_group_name" {
  type = string
}

variable "az_apim_service_name" {
  type = string
}

provider "az-confidential" {
  tenant_id       = var.az_tenant_id
  subscription_id = var.az_subscription_id
  client_id       = var.az_client_id
  client_secret   = var.az_client_secret

  labels       = ["acceptance-testing"]

  default_destination_vault_name = var.az_default_vault_name

  default_wrapping_key = {
    vault_name = var.az_default_vault_name
    name       = var.az_default_wrapping_key
    version    = var.az_default_wrapping_key_version
  }
}