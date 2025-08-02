package model

import (
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

type CLIOption string

func (c CLIOption) Opt() string {
	return fmt.Sprintf("-%s", c)
}

func (c CLIOption) String() string {
	return string(c)
}

type TerraformCode string

func (t TerraformCode) String() string {
	return string(t)
}

type Ciphertext string

func (c Ciphertext) String() string {
	return string(c)
}

type GroupDispatch func(command string, kwp ContentWrappingParams, args []string) (SubCommandExecution, error)

type SubCommandExecution func(inputReader InputReader) (TerraformCode, core.EncryptedMessage, error)

type InputReader func(prompt, fn string, base64Decode bool, multiline bool) ([]byte, error)
