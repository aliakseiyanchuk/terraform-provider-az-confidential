package tfgen

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/io"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"os"
	"strings"
	"sync"
	"time"
)

var commandGroups []string

type EntryPointCLIArgs struct {
	WrappingKeyCoordinate core.WrappingKeyCoordinate
	RSAPublicKeyFile      string

	ProviderConstraints string
	ConstraintTarget    bool

	PrintCiphertextOnly bool

	CreateLimit time.Duration
	ExpiryDays  int
	NumUses     int
	CreateOnce  bool

	NoCreateLimit bool
	NoExpireLimit bool
	NoUsageLimit  bool
}

func init() {
	commandGroups = []string{
		"kv",
		"apim",
	}
}

func CreateCommonCLIArgs() (*EntryPointCLIArgs, *flag.FlagSet) {
	rv := &EntryPointCLIArgs{}

	var baseFlags = flag.NewFlagSet("tfgen", flag.ExitOnError)
	baseFlags.SetOutput(os.Stdout)

	baseFlags.StringVar(&rv.WrappingKeyCoordinate.VaultName,
		"wrapping-key-vault",
		"",
		"Vault containing the wrapping key")

	baseFlags.StringVar(&rv.WrappingKeyCoordinate.KeyName,
		"wrapping-key-name",
		"",
		"Wrapping/encrypting key name")

	baseFlags.StringVar(&rv.WrappingKeyCoordinate.KeyVersion,
		"wrapping-key-version",
		"",
		"Wrapping/encrypting key version")

	baseFlags.StringVar(&rv.RSAPublicKeyFile,
		"pubkey",
		"",
		"RSA public key to encrypt secrets/content encryption keys",
	)

	baseFlags.StringVar(&rv.ProviderConstraints,
		"provider-constraints",
		"",
		"Require the provider deploying a resource from the ciphertext to be configured with the specified provider label. Use comma to separate individual labels",
	)

	baseFlags.BoolVar(&rv.ConstraintTarget,
		"lock-destination",
		false,
		"The ciphertext may only be used to create an Azure resource with the configuration "+
			"specified when the ciphertext is created. For example, when creating a kv key resource, you can specify a specific "+
			"vault name and key name. Exact option depend on the resource type.",
	)

	baseFlags.DurationVar(&rv.CreateLimit,
		"time-to-create",
		time.Hour*24*3,
		"Time before a resource can be created. Defaults to 3 calendar days. Use -no-create-limit to remove this limit.",
	)

	baseFlags.BoolVar(&rv.NoCreateLimit,
		"no-create-limit",
		false,
		"Removes the timing limit on create from the ciphertext",
	)

	baseFlags.IntVar(&rv.ExpiryDays,
		"days-to-expire",
		365,
		"Days the ciphertext remains valid. Defaults to 365 days. Use -no-expiry-limit to remove this limit",
	)

	baseFlags.BoolVar(&rv.NoExpireLimit,
		"no-expiry-limit",
		false,
		"Removes the expiry date from  ciphertext. The ciphertext will be perpetually valid.",
	)

	baseFlags.IntVar(&rv.NumUses,
		"num-uses",
		10,
		"Number of times this ciphertext can be used to create object. Defaults to 10. Set to zero to disable this limit",
	)

	baseFlags.BoolVar(&rv.CreateOnce,
		"create-once",
		false,
		"Create this resource once. A shortcut for `-num-uses 1`",
	)

	baseFlags.BoolVar(&rv.NoUsageLimit,
		"no-usage-limit",
		false,
		"Removes the limit on ciphertext usages. The ciphertext can be used any number of times.",
	)

	baseFlags.BoolVar(&rv.PrintCiphertextOnly,
		"ciphertext-only",
		false,
		"Output only ciphertext (i.e. do not output associated Terraform code template)",
	)

	return rv, baseFlags
}

func buildContentWrappingParams(cliArgs *EntryPointCLIArgs) (*model.ContentWrappingParams, error) {

	var providerConstraints []core.ProviderConstraint
	if len(cliArgs.ProviderConstraints) > 0 {
		for _, s := range strings.Split(cliArgs.ProviderConstraints, ",") {
			providerConstraints = append(providerConstraints, core.ProviderConstraint(s))
		}
	}

	createLimit := int64(0)
	if !cliArgs.NoCreateLimit {
		createLimit = time.Now().Add(cliArgs.CreateLimit).Unix()
	}

	expiryLimit := int64(0)
	if !cliArgs.NoExpireLimit {
		expiryLimit = time.Now().Add(time.Hour * time.Duration(24*cliArgs.ExpiryDays)).Unix()
	}

	numUses := -1
	if cliArgs.CreateOnce {
		numUses = 1
	} else if !cliArgs.NoUsageLimit {
		numUses = cliArgs.NumUses
	}

	rv := &model.ContentWrappingParams{
		SecondaryProtectionParameters: core.SecondaryProtectionParameters{
			ProviderConstraints:  providerConstraints,
			PlacementConstraints: nil,
			CreateLimit:          createLimit,
			Expiry:               expiryLimit,
			NumUses:              numUses,
		},
		WrappingKeyCoordinate: model.NewWrappingKey(),
		LoadRsaPublicKey: sync.OnceValues(func() (*rsa.PublicKey, error) {
			pubKeyData, pubKeyReadErr := io.ReadInput("Please provide public key of the key wrapping key", cliArgs.RSAPublicKeyFile, false, true)
			if pubKeyReadErr != nil {
				return nil, fmt.Errorf("cannot read public key: %s", pubKeyReadErr.Error())
			}

			loadedRSAKey, rsaLoadErr := core.LoadPublicKeyFromData(pubKeyData)
			if rsaLoadErr != nil {
				return nil, fmt.Errorf("failed to load public key (-pubkey argument was '%s'): %s", cliArgs.RSAPublicKeyFile, rsaLoadErr)
			}
			return loadedRSAKey, nil
		}),
		LockPlacement: cliArgs.ConstraintTarget,
	}

	if len(cliArgs.WrappingKeyCoordinate.VaultName) > 0 {
		rv.WrappingKeyCoordinate.VaultName.SetValue(cliArgs.WrappingKeyCoordinate.VaultName)
	}
	if len(cliArgs.WrappingKeyCoordinate.KeyName) > 0 {
		rv.WrappingKeyCoordinate.KeyName.SetValue(cliArgs.WrappingKeyCoordinate.KeyName)
	}
	if len(cliArgs.WrappingKeyCoordinate.KeyVersion) > 0 {
		rv.WrappingKeyCoordinate.KeyVersion.SetValue(cliArgs.WrappingKeyCoordinate.KeyVersion)
	}
	if len(cliArgs.WrappingKeyCoordinate.Algorithm) > 0 {
		rv.WrappingKeyCoordinate.Algorithm.SetValue(cliArgs.WrappingKeyCoordinate.Algorithm)
	}

	return rv, nil
}

// MainEntryPoint entry point that a wrapping CLI tool should use to trigger the CLI pocessing.
func MainEntryPoint() {

	cliArgs, baseFlags := CreateCommonCLIArgs()

	if parseErr := baseFlags.Parse(os.Args[1:]); parseErr != nil {
		_, _ = fmt.Printf("Invalid command line: %s", parseErr.Error())
		flag.PrintDefaults()
		os.Exit(1)
	}

	if len(baseFlags.Args()) < 2 {
		fmt.Println("Missing command group and command")
		printSubcommandSelectionHelp(baseFlags)
		os.Exit(1)
	}

	kwp, kwpErr := buildContentWrappingParams(cliArgs)
	if kwpErr != nil {
		fmt.Printf("Error in base arguments: %s\n", kwpErr.Error())
		printSubcommandSelectionHelp(baseFlags)
		os.Exit(1)
	}

	cmdGroup := baseFlags.Args()[0]
	cmd := baseFlags.Args()[1]
	cmdArgs := baseFlags.Args()[2:]

	var generator model.SubCommandExecution
	var generatorInitErr error

	switch cmdGroup {
	case "general":
		generator, generatorInitErr = general.EntryPoint(kwp, cmd, cmdArgs)
	case "kv":
		generator, generatorInitErr = keyvault.EntryPoint(kwp, cmd, cmdArgs)
	case "apim":
		generator, generatorInitErr = apim.EntryPoint(kwp, cmd, cmdArgs)
	default:
		_, _ = fmt.Printf("Unknown subcommand: %s", cmdGroup)
		printSubcommandSelectionHelp(baseFlags)
		os.Exit(1)
	}

	if generatorInitErr != nil {
		// Error message must be printed by the sub-command
		fmt.Println("Cannot produce template:")
		fmt.Println(generatorInitErr.Error())
		os.Exit(2)
	}

	tfCode, err := generator(io.ReadInput, cliArgs.PrintCiphertextOnly)
	if err != nil {
		// Error message must be printed by the sub-command
		fmt.Println("Cannot produce template:")
		fmt.Println(err.Error())
		os.Exit(2)
	}

	fmt.Println(tfCode)
	// End of program
}

func printSubcommandSelectionHelp(f *flag.FlagSet) {
	fmt.Println("Usage: tfgen [<standard options>] <group> <subcommand> [<args>]")
	fmt.Println("Possible command groups are:")
	for _, cmd := range commandGroups {
		fmt.Printf("- %s", cmd)
		fmt.Println()
	}
	fmt.Println("Running tfgen <group> help will print further information about this command")
	fmt.Println()
	f.PrintDefaults()
}
