package tfgen

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"strings"
	"text/template"
	"time"
)

type WrappingKeyCoordinateTFCode struct {
	core.WrappingKeyCoordinate

	VaultNameIsExpr  bool
	KeyNameIsExpr    bool
	KeyVersionIsExpr bool
}

func (w *WrappingKeyCoordinateTFCode) VaultNameExpr() string {
	if w.VaultNameIsExpr {
		return w.VaultName
	} else {
		return types.StringValue(w.VaultName).String()
	}
}

func (w *WrappingKeyCoordinateTFCode) KeyNameExpr() string {
	if w.KeyNameIsExpr {
		return w.KeyName
	} else {
		return types.StringValue(w.KeyName).String()
	}
}

func (w *WrappingKeyCoordinateTFCode) KeyVersionExpr() string {
	if w.KeyVersionIsExpr {
		return w.KeyVersion
	} else {
		return types.StringValue(w.KeyName).String()
	}
}

type AzKeyVaultObjectCoordinateTFCode struct {
	core.AzKeyVaultObjectCoordinate
	VaultNameIsExpr  bool
	ObjectNameIsExpr bool
}

func (w *AzKeyVaultObjectCoordinateTFCode) GetVaultNameExpr() string {
	if w.VaultNameIsExpr {
		return w.VaultName
	} else {
		return types.StringValue(w.VaultName).String()
	}
}

func (w *AzKeyVaultObjectCoordinateTFCode) GetObjectNameExpr() string {
	if w.ObjectNameIsExpr {
		return w.Name
	} else {
		return types.StringValue(w.Name).String()
	}
}

type ContentWrappingParams struct {
	RSAPublicKeyFile      string
	NoLabels              bool
	Labels                string
	TargetCoordinateLabel bool
	LoadedRsaPublicKey    *rsa.PublicKey

	TFBlockName string

	WrappingKeyCoordinate WrappingKeyCoordinateTFCode
	DestinationCoordinate AzKeyVaultObjectCoordinateTFCode
}

func (kpw *ContentWrappingParams) TFBlockNameIfUndefined(v string) {
	if len(kpw.TFBlockName) == 0 {
		kpw.TFBlockName = v
	}
}

func (kwp *ContentWrappingParams) GetLabels() []string {
	if kwp.TargetCoordinateLabel {
		return []string{kwp.DestinationCoordinate.GetLabel()}
	} else if len(kwp.Labels) > 0 {
		return strings.Split(kwp.Labels, ",")
	} else {
		return nil
	}
}

func (kwp *ContentWrappingParams) ValidateHasDestination() error {
	if len(kwp.DestinationCoordinate.Name) == 0 {
		return fmt.Errorf("destination key name is required; use -output-vault-secret option")
	}
	if len(kwp.DestinationCoordinate.VaultName) == 0 {
		return fmt.Errorf("destination vault name is required; use -output-vault option")
	}

	return nil
}

func (kwp *ContentWrappingParams) Validate() error {

	pubKeyData, pubKeyReadErr := ReadInput("Please provide public key of the key wrapping key", kwp.RSAPublicKeyFile, false, true)
	if pubKeyReadErr != nil {
		return fmt.Errorf("cannot read public key: %s", pubKeyReadErr.Error())
	}

	loadedRSAKey, rsaLoadErr := core.LoadPublicKeyFromData(pubKeyData)
	if rsaLoadErr != nil {
		return fmt.Errorf("failed to load public key (-pubkey argument was '%s'): %s", kwp.RSAPublicKeyFile, rsaLoadErr)
	} else {
		kwp.LoadedRsaPublicKey = loadedRSAKey
	}

	if !kwp.TargetCoordinateLabel && (len(kwp.Labels) == 0 && !kwp.NoLabels) {
		return errors.New("missing instruction for provider label matching; ensure to use -no-label if you intend to disable label matching")
	}

	if kwp.TargetCoordinateLabel && len(kwp.Labels) > 0 {
		return errors.New("conflicting matching requirements: target coordinate labelling cannot be used with fixed labelling")
	}

	return nil
}

type BaseTFTemplateParms struct {
	EncryptedContent string

	TFBlockName string

	WrappingKeyCoordinate WrappingKeyCoordinateTFCode
	DestinationCoordinate AzKeyVaultObjectCoordinateTFCode

	IncludeTags bool
	Tags        map[string]string
	Labels      []string
}

func (p *BaseTFTemplateParms) HasTags() bool {
	return len(p.Tags) > 0
}

func (p *BaseTFTemplateParms) HasLabels() bool {
	return len(p.Labels) > 0
}

func (p *BaseTFTemplateParms) TerraformValueTags() map[string]string {
	rv := make(map[string]string, len(p.Tags))

	if p.Tags == nil {
		return rv
	}

	for k, v := range p.Tags {
		rv[k] = types.StringValue(v).String()
	}

	return rv
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
	return p.RenderObject(templateName, templateStr, p)
}

func (p *BaseTFTemplateParms) RenderObject(templateName, templateStr string, obj interface{}) (string, error) {
	tmpl, templErr := template.New(templateName).Parse(templateStr)
	if templErr != nil {
		panic(templErr)
	}

	var rv bytes.Buffer
	err := tmpl.Execute(&rv, obj)

	return rv.String(), err
}

func (p *BaseTFTemplateParms) DefinesWrappingCoordinate() bool {
	return !p.WrappingKeyCoordinate.IsEmpty()
}
