package tfgen

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"os"
	"strings"
	"text/template"
	"time"
)

type KeyWrappingParams struct {
	RSAPublicKeyFile   string
	NoOAEPLabel        bool
	FixedOAEPLabel     string
	StrictOAEPLabel    bool
	LoadedRsaPublicKey *rsa.PublicKey

	WrappingKeyCoordinate core.WrappingKeyCoordinate
	DestinationCoordinate core.AzKeyVaultObjectCoordinate
}

func (kwp *KeyWrappingParams) GetLabels() []string {
	if kwp.StrictOAEPLabel {
		return []string{kwp.DestinationCoordinate.GetOAEPLabel()}
	} else if len(kwp.FixedOAEPLabel) > 0 {
		return strings.Split(kwp.FixedOAEPLabel, ",")
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

	if len(kwp.RSAPublicKeyFile) == 0 {
		return fmt.Errorf("public key to use required; use -pubkey option")
	}

	if _, err := os.Stat(kwp.RSAPublicKeyFile); err != nil {
		return fmt.Errorf("public key file '%s' does not exist; correct -pubkey option", kwp.RSAPublicKeyFile)
	}

	loadedRSAKey, rsaLoadErr := core.LoadPublicKey(kwp.RSAPublicKeyFile)
	if rsaLoadErr != nil {
		return fmt.Errorf("failed to load public key file '%s': %s", kwp.RSAPublicKeyFile, rsaLoadErr)
	} else {
		kwp.LoadedRsaPublicKey = loadedRSAKey
	}

	if !kwp.StrictOAEPLabel && len(kwp.FixedOAEPLabel) == 0 && !kwp.NoOAEPLabel {
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
