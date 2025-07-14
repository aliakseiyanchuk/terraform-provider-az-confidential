package general

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

var subcommands = []string{
	"password",
}

// EntryPoint entry point that a wrapping CLI tool should use to trigger the CLI pocessing.
func EntryPoint(kwp *model.ContentWrappingParams, command string, args []string) (model.SubCommandExecution, error) {
	switch command {
	case "password":
		return MakePasswordGenerator(kwp, args)
	default:
		return nil, fmt.Errorf("unknown subcommand: %s", command)
	}
}

func printSubcommandSelectionHelp() {
	fmt.Println("Usage: tfgen [<standard options>] general <subcommand> [<args>]")
	fmt.Println("Possible sub-commands are:")
	for _, cmd := range subcommands {
		fmt.Printf("- %s", cmd)
		fmt.Println()
	}
}
