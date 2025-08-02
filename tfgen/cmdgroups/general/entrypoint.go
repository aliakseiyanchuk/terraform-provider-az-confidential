package general

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"os"
)

var subcommands = []string{
	"password",
}

// EntryPoint entry point that a wrapping CLI tool should use to trigger the CLI pocessing.
func EntryPoint(kwp *model.ContentWrappingParams, command string, args []string) (model.SubCommandExecution, error) {
	switch command {
	case "help":
		printSubcommandSelectionHelp()
		os.Exit(2)
		return nil, nil
	case ContentCommand:
		return MakeContentGenerator(kwp, args)
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
