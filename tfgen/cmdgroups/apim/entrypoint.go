package apim

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"os"
)

var subcommands = []string{
	NamedValueCommand,
	SubscriptionCommand,
}

// EntryPoint entry point that a wrapping CLI tool should use to trigger the CLI processing.
func EntryPoint(kwp *model.ContentWrappingParams, command string, args []string) (model.SubCommandExecution, error) {

	switch command {
	case "help":
		printSubcommandSelectionHelp()
		os.Exit(2)
		return nil, nil
	case NamedValueCommand:
		return MakeNamedValueGenerator(kwp, args)
	case SubscriptionCommand:
		return MakeSubscriptionGenerator(kwp, args)
	default:
		return nil, fmt.Errorf("unknown subcommand: %s", command)
	}
}

func printSubcommandSelectionHelp() {
	fmt.Println("Usage: tfgen [<standard options>] generic <subcommand> [<args>]")
	fmt.Println("Possible sub-commands are:")
	for _, cmd := range subcommands {
		fmt.Printf("- %s", cmd)
		fmt.Println()
	}
}
