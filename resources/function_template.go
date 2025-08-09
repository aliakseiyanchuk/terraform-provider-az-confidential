package resources

import (
	"context"
	"crypto/rsa"
	_ "embed"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"maps"
	"time"
)

type PublicKeyValidator struct{}

func (pkv *PublicKeyValidator) ValidateParameterString(_ context.Context, req function.StringParameterValidatorRequest, res *function.StringParameterValidatorResponse) {
	if _, err := core.LoadPublicKeyFromData([]byte(req.Value.ValueString())); err != nil {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError(fmt.Sprintf("incorrect public key %s", err.Error())))
	}
}

type AttributeTyped interface {
	GetAttributeTypes() map[string]attr.Type
	GetMarkdownDescription() string
}

type Exportable interface {
	Into(ctx context.Context, c *core.SecondaryProtectionParameters) error
}

type ProtectionParameterized interface {
	AttributeTyped
	Exportable
}

type ProtectionParams struct {
	ExpiresAfterDays    types.Int32 `tfsdk:"expires_after"`
	NumUses             types.Int32 `tfsdk:"num_uses"`
	ProviderConstraints types.Set   `tfsdk:"provider_constraints"`
}

//go:embed protection_params.md
var protectionParamsMarkdown string

func (p ProtectionParams) GetMarkdownDescription() string {
	return protectionParamsMarkdown
}

func (p ProtectionParams) GetAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"num_uses":      types.Int32Type,
		"expires_after": types.Int32Type,
		"provider_constraints": types.SetType{
			ElemType: types.StringType,
		},
	}
}

type LimitedCreateProtectionParam struct {
	CreateLimit types.String `tfsdk:"create_limit"`
}

func (p LimitedCreateProtectionParam) GetAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"create_limit": types.StringType,
	}
}

type ResourceProtectionParams struct {
	ProtectionParams
	LimitedCreateProtectionParam
}

func (p ResourceProtectionParams) GetAttributeTypes() map[string]attr.Type {
	rv := map[string]attr.Type{}
	maps.Copy(rv, p.ProtectionParams.GetAttributeTypes())
	maps.Copy(rv, p.LimitedCreateProtectionParam.GetAttributeTypes())

	return rv
}

//go:embed resource_protection_params.md
var resourceProtectionParamsMarkdown string

func (p ResourceProtectionParams) GetMarkdownDescription() string {
	return resourceProtectionParamsMarkdown
}

func (p ResourceProtectionParams) Into(ctx context.Context, c *core.SecondaryProtectionParameters) error {
	if err := p.ProtectionParams.Into(ctx, c); err != nil {
		return err
	}
	if err := p.LimitedCreateProtectionParam.Into(c); err != nil {
		return err
	}

	return nil
}

func (p ProtectionParams) Into(ctx context.Context, c *core.SecondaryProtectionParameters) error {
	if !p.ExpiresAfterDays.IsUnknown() && !p.ExpiresAfterDays.IsNull() {
		c.Expiry = time.Now().Add(time.Hour * time.Duration(24*int(p.ExpiresAfterDays.ValueInt32()))).Unix()
	}

	if !p.NumUses.IsUnknown() && !p.NumUses.IsNull() {
		c.NumUses = int(p.NumUses.ValueInt32())
	}

	if len(p.ProviderConstraints.Elements()) > 0 {
		var elems []string
		p.ProviderConstraints.ElementsAs(ctx, &elems, true)

		c.ProviderConstraints = make([]core.ProviderConstraint, len(elems))
		for i, elem := range elems {
			c.ProviderConstraints[i] = core.ProviderConstraint(elem)
		}
	}

	return nil

}
func (p LimitedCreateProtectionParam) Into(c *core.SecondaryProtectionParameters) error {
	if !p.CreateLimit.IsUnknown() && !p.CreateLimit.IsNull() && len(p.CreateLimit.ValueString()) > 0 {
		d, durErr := time.ParseDuration(p.CreateLimit.ValueString())
		if durErr != nil {
			return durErr
		}

		c.CreateLimit = time.Now().Unix() + int64(d.Seconds())
	}

	return nil
}

type FunctionTemplate[TMdl any, TProtection ProtectionParameterized, DestMdl any] struct {
	Name                                    string
	Summary                                 string
	MarkdownDescription                     string
	DataParameter                           function.Parameter
	ProtectionParameterSupplier             core.Supplier[TProtection]
	DestinationParameter                    function.Parameter
	DestinationParameterMarkdownDescription string
	ConfidentialModelSupplier               core.Supplier[TMdl]
	DestinationModelSupplier                core.Supplier[*DestMdl]
	CreatEncryptedMessage                   func(confidentialModel TMdl, dest *DestMdl, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, error)
}

func (f *FunctionTemplate[TMdl, TProtection, DestMdl]) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = f.Name
}

func (f *FunctionTemplate[TMdl, TProtection, DestMdl]) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	funcParams := []function.Parameter{
		f.DataParameter,
	}
	if f.DestinationParameter != nil {
		funcParams = append(funcParams, f.DestinationParameter)
	}

	protectionParam := f.ProtectionParameterSupplier()

	funcParams = append(funcParams,
		function.ObjectParameter{
			Name:           "content_protection",
			Description:    "Secondary content protection parameters to be embedded into the output ciphertext. See the details about the object fields above.",
			AllowNullValue: true,

			AttributeTypes: protectionParam.GetAttributeTypes(),
		},
		function.StringParameter{
			Name:        "public_key",
			Description: "Public key of the Key-Wrapping Key",
			Validators: []function.StringParameterValidator{
				&PublicKeyValidator{},
			},
		},
	)

	resp.Definition = function.Definition{
		Summary: f.Summary,
		MarkdownDescription: f.MarkdownDescription +
			"\n" +
			protectionParam.GetMarkdownDescription() +
			"\n" +
			f.DestinationParameterMarkdownDescription,
		Return: function.StringReturn{},

		Parameters: funcParams,
	}
}

func (f *FunctionTemplate[TMdl, TProtection, DestMdl]) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	confidentialModel := f.ConfidentialModelSupplier()
	destinationModel := f.DestinationModelSupplier()
	var headerParams *TProtection
	var publicKey string

	if f.DestinationParameter != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &confidentialModel, &destinationModel, &headerParams, &publicKey))
	} else {
		resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &confidentialModel, &headerParams, &publicKey))
	}
	// Read Terraform argument data into the variable
	if resp.Error != nil {
		return
	}

	pubKey, err := core.LoadPublicKeyFromData([]byte(publicKey))
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewFuncError(fmt.Sprintf("incorrect public key: %s", err.Error())))
		return
	}

	md := core.SecondaryProtectionParameters{}
	if headerParams != nil {
		if copyErr := (*headerParams).Into(ctx, &md); copyErr != nil {
			resp.Error = function.ConcatFuncErrors(resp.Error, function.NewFuncError(fmt.Sprintf("incorrect content protection parameters: %s", copyErr.Error())))
			return
		}
	}

	em, err := f.CreatEncryptedMessage(confidentialModel, destinationModel, md, pubKey)
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewFuncError(fmt.Sprintf("unable to encrupt supplied data: %s", err.Error())))
		return
	}

	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, em.ToBase64PEM()))
}
