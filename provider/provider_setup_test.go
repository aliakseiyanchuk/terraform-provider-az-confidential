package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	_ "github.com/hashicorp/terraform-plugin-mux/tf6muxserver"
	"os"
)

const (
	providerConfig = `
provider "az-confidential" {
  tenant_id       = var.az_tenant_id
  subscription_id = var.az_subscription_id
  client_id       = var.az_client_id
  client_secret   = var.az_client_secret

  oaep_label       = "ZGVtbw=="
  oaep_enforcement = "fixed"

  default_destination_vault_name = var.az_default_vault_name

  default_wrapping_key = {
    vault_name = var.az_default_vault_name
    name       = var.az_default_wrapping_key
    version    = var.az_default_wrapping_key_version
  }
}
`
)

var (
	// testAccProtoV6ProviderFactories are used to instantiate a provider during
	// acceptance testing. The factory function will be invoked for every Terraform
	// CLI command executed to create a provider server to which the CLI can
	// reattach.
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"az-confidential": providerserver.NewProtocol6WithError(New("test")()),
	}

	// Load the wrapping key for automatic encryption
	wrappingKey = os.Getenv("AZ_CONFIDENTIAL_WRAPPING_PUBEY")
)
