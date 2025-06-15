package acceptance

import (
	_ "embed"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"os"
)

//go:embed test_provider_config.tf
var providerConfig string

var (
	// testAccProtoV6ProviderFactories are used to instantiate a provider during
	// acceptance testing. The factory function will be invoked for every Terraform
	// CLI command executed to create a provider server to which the CLI can
	// reattach.
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"az-confidential": providerserver.NewProtocol6WithError(provider.New("test")()),
	}

	// Load the wrapping key for automatic encryption
	wrappingKey = os.Getenv("AZ_CONFIDENTIAL_WRAPPING_PUBKEY")
)

func init() {
	if len(wrappingKey) == 0 {
		wrappingKey = "/Users/aliakseiyanchuk/GolandProjects/ConfidentialKVEntries/wrapping_key_pk.pem"
	}
}
