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

variable "content" {
  type        = string
  description = "Content that needs to be wrapped"
}