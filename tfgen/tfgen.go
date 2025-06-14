package main

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"os"
	"strings"
	"text/template"
	"time"
)

type KeyWrappingParams struct {
	rsaPublicKeyFile   string
	noOAEPLabel        bool
	fixedOAEPLabel     string
	strictOAEPLabel    bool
	loadedRsaPublicKey *rsa.PublicKey

	WrappingKeyCoordinate core.WrappingKeyCoordinate
	DestinationCoordinate core.AzKeyVaultObjectCoordinate
}

func (kwp *KeyWrappingParams) GetLabels() []string {
	if kwp.strictOAEPLabel {
		return []string{kwp.DestinationCoordinate.GetOAEPLabel()}
	} else if len(kwp.fixedOAEPLabel) > 0 {
		return strings.Split(kwp.fixedOAEPLabel, ",")
	} else {
		return nil
	}
}

func (kwp *KeyWrappingParams) ValidateHasDestination() error {
	if len(kwp.DestinationCoordinate.Name) == 0 {
		return fmt.Errorf("destination key name is required; use -output-vault-secret option")
	}
	if len(kwp.DestinationCoordinate.VaultName) == 0 {
		return fmt.Errorf("destination vault name is required; use -output-vault option")
	}

	return nil
}

func (kwp *KeyWrappingParams) Validate() error {

	if len(kwp.rsaPublicKeyFile) == 0 {
		return fmt.Errorf("public key to use required; use -pubkey option")
	}

	if _, err := os.Stat(kwp.rsaPublicKeyFile); err != nil {
		return fmt.Errorf("public key file '%s' does not exist; correct -pubkey option", kwp.rsaPublicKeyFile)
	}

	loadedRSAKey, rsaLoadErr := core.LoadPublicKey(kwp.rsaPublicKeyFile)
	if rsaLoadErr != nil {
		return fmt.Errorf("failed to load public key file '%s': %s", kwp.rsaPublicKeyFile, rsaLoadErr)
	} else {
		kwp.loadedRsaPublicKey = loadedRSAKey
	}

	if !kwp.strictOAEPLabel && len(kwp.fixedOAEPLabel) == 0 && !kwp.noOAEPLabel {
		return errors.New("missing instruction for OAEP label; did you forget -no-oaep-label")
	}

	return nil
}

type BaseTFTemplateParms struct {
	EncryptedContent     string
	ContentEncryptionKey string

	WrappingKeyCoordinate core.WrappingKeyCoordinate
	DestinationCoordinate core.AzKeyVaultObjectCoordinate
}

func (p *BaseTFTemplateParms) NotBeforeExample() string {
	t := time.Now()
	return core.FormatTime(&t).ValueString()
}

func (p *BaseTFTemplateParms) NotAfterExample() string {
	t := time.Now().AddDate(1, 0, 0)
	return core.FormatTime(&t).ValueString()
}

func (p *BaseTFTemplateParms) Render(templateName, templateStr string) (string, error) {
	tmpl, _ := template.New(templateName).Parse(templateStr)
	var rv bytes.Buffer
	err := tmpl.Execute(&rv, p)

	return rv.String(), err
}

func (p *BaseTFTemplateParms) DefinesCEK() bool {
	return len(p.ContentEncryptionKey) > 0
}

func (p *BaseTFTemplateParms) DefinesWrappingCoordinate() bool {
	return !p.WrappingKeyCoordinate.IsEmpty()
}

var baseParams = KeyWrappingParams{
	noOAEPLabel:     false,
	fixedOAEPLabel:  "",
	strictOAEPLabel: false,
}

var baseFlags = flag.NewFlagSet("base", flag.ExitOnError)

var subcommands []string

func init() {
	subcommands = []string{
		"secret",
		"password",
		"key",
		"certificate",
	}

	baseFlags.SetOutput(os.Stdout)
	baseFlags.StringVar(&baseParams.DestinationCoordinate.VaultName,
		"output-vault",
		"",
		"Output vault name")

	baseFlags.StringVar(&baseParams.DestinationCoordinate.Name,
		"output-vault-object",
		"",
		"Output vault object name")

	baseFlags.StringVar(&baseParams.WrappingKeyCoordinate.VaultName,
		"wrapping-key-vault",
		"",
		"Vault containing the wrapping key")

	baseFlags.StringVar(&baseParams.WrappingKeyCoordinate.KeyName,
		"wrapping-key-name",
		"",
		"Wrapping/encrypting key name")

	baseFlags.StringVar(&baseParams.WrappingKeyCoordinate.KeyVersion,
		"wrapping-key-version",
		"",
		"Wrapping/encrypting key version")

	baseFlags.StringVar(&baseParams.rsaPublicKeyFile,
		"pubkey",
		"",
		"RSA public key to encrypt secrets/content encryption keys",
	)

	baseFlags.BoolVar(&baseParams.noOAEPLabel,
		"no-oaep-label",
		true,
		"No not use any labels",
	)

	baseFlags.StringVar(&baseParams.fixedOAEPLabel,
		"fixed-oaep-label",
		"",
		"Fixed OAEP label to use",
	)

	baseFlags.BoolVar(&baseParams.strictOAEPLabel,
		"strict-oaep-label",
		true,
		"Use strict OAEP label",
	)
}

func main() {
	if parseErr := baseFlags.Parse(os.Args[1:]); parseErr != nil {
		_, _ = fmt.Printf("Invalid command line: %s", parseErr.Error())
		flag.PrintDefaults()
		os.Exit(1)
	}

	if len(baseFlags.Args()) == 0 {
		fmt.Println("Missing subcommand")
		printSubcommandSelectionHelp()
		os.Exit(1)
	}

	subCmd := baseFlags.Args()[0]
	var generator func(KeyWrappingParams, []string) (string, error)

	switch subCmd {
	case "secret":
		generator = generateConfidentialSecretTerraformTemplate
	case "password":
		generator = generateConfidentialPasswordTemplate
	case "key":
		generator = generateConfidentialKeyTerraformTemplate
	case "certificate":
		generator = generateConfidentialCertificateTerraformTemplate
	default:
		_, _ = fmt.Printf("Unknown subcommand: %s", subCmd)
		printSubcommandSelectionHelp()
		os.Exit(1)
	}

	if validationErr := baseParams.Validate(); validationErr != nil {
		_, _ = fmt.Printf("Incorrect basic arguments: %s", validationErr.Error())
		flag.PrintDefaults()
		os.Exit(1)
	}

	tfCode, err := generator(baseParams, baseFlags.Args()[1:])
	if err != nil {
		// Error message must be printed by the sub-command
		fmt.Println("Cannot produce template:")
		fmt.Println(err.Error())
		os.Exit(2)
	}

	fmt.Println(tfCode)

	// End of program
}

func printSubcommandSelectionHelp() {
	fmt.Println("Usage: tfgen [<standard options>] <subcommand> [<args>]")
	fmt.Println("Possible sub-commands are:")
	for _, cmd := range subcommands {
		fmt.Printf("- %s", cmd)
		fmt.Println()
	}
}
