package keyvault

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"os"
)

var subcommands = []string{
	SecretCommand,
	KeyCommand,
	CertificateCommand,
}

// EntryPoint entry point that a wrapping CLI tool should use to trigger the CLI processing.
func EntryPoint(kwp *model.ContentWrappingParams, command string, args []string) (model.SubCommandExecution, error) {
	switch command {
	case "help":
		PrintGroupHelp()
		os.Exit(2)
		return nil, nil
	case SecretCommand:
		return MakeSecretGenerator(kwp, args)
	case KeyCommand:
		return MakeKeyGenerator(kwp, args...)
	case CertificateCommand:
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
