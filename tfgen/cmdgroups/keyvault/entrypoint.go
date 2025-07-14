package keyvault

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

var subcommands = []string{
	"secret",
	"key",
	"certificate",
}

// EntryPoint entry point that a wrapping CLI tool should use to trigger the CLI pocessing.
func EntryPoint(kwp *model.ContentWrappingParams, command string, args []string) (model.SubCommandExecution, error) {
	switch command {
	case "secret":
		return MakeSecretGenerator(kwp, args)
	case "key":
		return MakeKeyGenerator(kwp, args...)
	case "certificate":
		return MakeCertGenerator(kwp, args...)
	default:
		return nil, fmt.Errorf("unknown subcommand: %s", command)
	}
}

func PrintGroupHelp() {
	fmt.Println("Usage: tfgen [<standard options>] kv <subcommand> [<args>]")
	fmt.Println("Possible sub-commands are:")
	for _, cmd := range subcommands {
		fmt.Printf("- %s", cmd)
		fmt.Println()
	}
}
