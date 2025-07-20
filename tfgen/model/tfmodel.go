package model

import (
	"bytes"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"text/template"
	"time"
)

type TagsModel struct {
	IncludeTags bool
	Tags        map[string]string
}

func (p *TagsModel) HasTags() bool {
	return len(p.Tags) > 0
}

func (p *TagsModel) GetTags() map[string]string {
	return p.Tags
}

func (p *TagsModel) TerraformValueTags() map[string]string {
	rv := make(map[string]string, len(p.Tags))

	if p.Tags == nil {
		return rv
	}

	for k, v := range p.Tags {
		rv[k] = types.StringValue(v).String()
	}

	return rv
}

type KeylessTagsModel struct {
	IncludeTags bool
	Tags        []string
}

func (p *KeylessTagsModel) HasTags() bool {
	return len(p.Tags) > 0
}

func (p *KeylessTagsModel) GetTags() []string {
	return p.Tags
}

func (p *KeylessTagsModel) TerraformValueTags() []string {
	rv := make([]string, len(p.Tags))

	if p.Tags == nil {
		return rv
	}

	for k, v := range p.Tags {
		rv[k] = types.StringValue(v).String()
	}

	return rv
}

type BaseTerraformCodeModel struct {
	TFBlockName string

	EncryptedContent TerraformFieldExpression[string]
	CiphertextLabels []string

	WrappingKeyCoordinate WrappingKey
}

func NewBaseTerraformCodeModel(kwp *ContentWrappingParams, blockName string) BaseTerraformCodeModel {
	return BaseTerraformCodeModel{
		TFBlockName:           blockName,
		CiphertextLabels:      kwp.GetLabels(),
		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		// The Terraform resources should be provided in the Heredoc
		// style for added readability.
		EncryptedContent: NewStringTerraformFieldHeredocExpression(),
	}
}

func (p *BaseTerraformCodeModel) HasCiphertextLabels() bool {
	return len(p.CiphertextLabels) > 0
}

func Render(templateName, templateStr string, obj interface{}) (string, error) {
	funcMap := template.FuncMap{
		"fold80": func(s string) []string { return FoldString(s, 80) },
	}

	tmpl, templErr := template.New(templateName).Funcs(funcMap).Parse(templateStr)
	if templErr != nil {
		panic(templErr)
	}

	var rv bytes.Buffer
	err := tmpl.Execute(&rv, obj)

	return rv.String(), err
}

func NotBeforeExample() string {
	t := time.Now()
	return core.FormatTime(&t).ValueString()
}

func NotAfterExample() string {
	t := time.Now().AddDate(1, 0, 0)
	return core.FormatTime(&t).ValueString()
}

func FoldString(v string, width int) []string {
	strLength := len(v)
	arrLength := strLength / width
	if strLength%width != 0 {
		arrLength++
	}

	rv := make([]string, arrLength)
	for i := 0; i*width < strLength; i++ {
		usableWidth := width
		if (i+1)*width > strLength {
			usableWidth = strLength - i*width
		}
		rv[i] = v[i*width : i*width+usableWidth]
	}

	return rv
}
