package tfgen

import (
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/general"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/cmdgroups/keyvault"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/io"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

const (
	PublicKeyPrompt = "Please provide public key of the key wrapping key"
)

const (
	ApimGroup     = "apim"
	GeneralGroup  = "general"
	KeyVaultGroup = "kv"
)

const (
	WrappingKeyVaultCliOption    model.CLIOption = "wrapping-key-vault"
	WrappingKeyNameCliOption     model.CLIOption = "wrapping-key-name"
	WrappingKeyVersion           model.CLIOption = "wrapping-key-version"
	PublicKeyCliOption           model.CLIOption = "pubkey"
	ProviderConstraintsCliOption model.CLIOption = "provider-constraints"
	LockDestinationCliOption     model.CLIOption = "lock-destination"
	TimeToCreateCliOption        model.CLIOption = "time-to-create"
	NoCreateLimitCliOption       model.CLIOption = "no-create-limit"
	DaysToExpireCliOption        model.CLIOption = "days-to-expire"
	NoExpiryLimitCliOption       model.CLIOption = "no-expiry-limit"
	NumberOfTimesUsesOption      model.CLIOption = "num-uses"
	CreateOnceOption             model.CLIOption = "create-once"
	NoUsageLimitOption           model.CLIOption = "no-usage-limit"
	CiphertextOnlyOption         model.CLIOption = "ciphertext-only"
)

var CommandGroups []string

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

func CreateCommonCLIArgs() (*EntryPointCLIArgs, *flag.FlagSet) {
	rv := &EntryPointCLIArgs{}

	var baseFlags = flag.NewFlagSet("tfgen", flag.ExitOnError)
	baseFlags.SetOutput(os.Stdout)

	baseFlags.StringVar(&rv.WrappingKeyCoordinate.VaultName,
		WrappingKeyVaultCliOption.String(),
		"",
		"Vault containing the wrapping key")

	baseFlags.StringVar(&rv.WrappingKeyCoordinate.KeyName,
		WrappingKeyNameCliOption.String(),
		"",
		"Wrapping/encrypting key name")

	baseFlags.StringVar(&rv.WrappingKeyCoordinate.KeyVersion,
		WrappingKeyVersion.String(),
		"",
		"Wrapping/encrypting key version")

	baseFlags.StringVar(&rv.RSAPublicKeyFile,
		PublicKeyCliOption.String(),
		"",
		"RSA public key to encrypt secrets/content encryption keys",
	)

	baseFlags.StringVar(&rv.ProviderConstraints,
		ProviderConstraintsCliOption.String(),
		"",
		"Require the provider deploying a resource from the ciphertext to be configured with the specified provider label. Use comma to separate individual labels",
	)

	baseFlags.BoolVar(&rv.ConstraintTarget,
		LockDestinationCliOption.String(),
		false,
		"The ciphertext may only be used to create an Azure resource with the configuration "+
			"specified when the ciphertext is created. For example, when creating a kv key resource, you can specify a specific "+
			"vault name and key name. Exact option depend on the resource type.",
	)

	baseFlags.DurationVar(&rv.CreateLimit,
		TimeToCreateCliOption.String(),
		time.Hour*24*3,
		"Time before a resource can be created. Defaults to 3 calendar days. Use -no-create-limit to remove this limit.",
	)

	baseFlags.BoolVar(&rv.NoCreateLimit,
		NoCreateLimitCliOption.String(),
		false,
		"Removes the timing limit on create from the ciphertext",
	)

	baseFlags.IntVar(&rv.ExpiryDays,
		DaysToExpireCliOption.String(),
		365,
		"Days the ciphertext remains valid. Defaults to 365 days. Use -no-expiry-limit to remove this limit",
	)

	baseFlags.BoolVar(&rv.NoExpireLimit,
		NoExpiryLimitCliOption.String(),
		false,
		"Removes the expiry date from  ciphertext. The ciphertext will be perpetually valid.",
	)

	baseFlags.IntVar(&rv.NumUses,
		NumberOfTimesUsesOption.String(),
		10,
		"Number of times this ciphertext can be used to create object. Defaults to 10. Set to zero to disable this limit",
	)

	baseFlags.BoolVar(&rv.CreateOnce,
		CreateOnceOption.String(),
		false,
		"Create this resource once. A shortcut for `-num-uses 1`",
	)

	baseFlags.BoolVar(&rv.NoUsageLimit,
		NoUsageLimitOption.String(),
		false,
		"Removes the limit on ciphertext usages. The ciphertext can be used any number of times.",
	)

	baseFlags.BoolVar(&rv.PrintCiphertextOnly,
		CiphertextOnlyOption.String(),
		false,
		"Output only ciphertext (i.e. do not output associated Terraform code template)",
	)

	return rv, baseFlags
}

func buildContentWrappingParams(ioReader model.InputReader, cliArgs *EntryPointCLIArgs) (*model.ContentWrappingParams, error) {

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

			pubKeyData, pubKeyReadErr := ioReader(PublicKeyPrompt, cliArgs.RSAPublicKeyFile, false, true)
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

func MainEntryPointDispatch(inputReader model.InputReader, allCmdArgs ...string) (*EntryPointCLIArgs, model.TerraformCode, core.EncryptedMessage, error) {
	cliArgs, baseFlags := CreateCommonCLIArgs()

	if parseErr := baseFlags.Parse(allCmdArgs); parseErr != nil {
		_, _ = fmt.Printf("Invalid command line: %s", parseErr.Error())
		flag.PrintDefaults()
		return nil, "", core.EncryptedMessage{}, parseErr
	}

	if len(baseFlags.Args()) < 2 {
		fmt.Println("Missing command group and command")
		printSubcommandSelectionHelp(baseFlags)
		return nil, "", core.EncryptedMessage{}, errors.New("missing command")
	}

	kwp, kwpErr := buildContentWrappingParams(inputReader, cliArgs)
	if kwpErr != nil {
		fmt.Printf("Error in base arguments: %s\n", kwpErr.Error())
		printSubcommandSelectionHelp(baseFlags)
		return nil, "", core.EncryptedMessage{}, errors.New("invalid base arguments")
	}

	cmdGroup := baseFlags.Args()[0]
	cmd := baseFlags.Args()[1]
	cmdArgs := baseFlags.Args()[2:]

	var generator model.SubCommandExecution
	var generatorInitErr error

	switch cmdGroup {
	case GeneralGroup:
		generator, generatorInitErr = general.EntryPoint(kwp, cmd, cmdArgs)
	case KeyVaultGroup:
		generator, generatorInitErr = keyvault.EntryPoint(kwp, cmd, cmdArgs)
	case ApimGroup:
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

	tfCode, en, err := generator(inputReader)
	if err != nil {
		// Error message must be printed by the sub-command
		fmt.Println("Cannot produce template:")
		fmt.Println(err.Error())
	}

	return cliArgs, tfCode, en, err
}

func printSubcommandSelectionHelp(f *flag.FlagSet) {
	fmt.Println("Usage: tfgen [<standard options>] <group> <subcommand> [<args>]")
	fmt.Println("Possible command groups are:")
	for _, cmd := range CommandGroups {
		fmt.Printf("- %s", cmd)
		fmt.Println()
	}
	fmt.Println("Running tfgen <group> help will print further information about this command")
	fmt.Println()
	f.PrintDefaults()
}

func init() {
	CommandGroups = []string{
		"kv",
		"apim",
	}
}

// MainEntryPoint entry point that a wrapping CLI tool should use to trigger the CLI processing.
func MainEntryPoint() {

	allCmdArgs := os.Args[1:]

	cliArgs, tfCode, en, err := MainEntryPointDispatch(io.ReadInput, allCmdArgs...)
	if err != nil {
		os.Exit(1)
	}

	if cliArgs.PrintCiphertextOnly {
		fld := model.FoldString(en.ToBase64PEM(), 80)
		for _, v := range strings.Join(fld, "\n") {
			fmt.Println(v)
		}
	} else {
		fmt.Println(tfCode)
	}

	// End of program
}
