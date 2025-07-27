package resources

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"time"
)

type PublicKeyValidator struct{}

func (pkv *PublicKeyValidator) ValidateParameterString(_ context.Context, req function.StringParameterValidatorRequest, res *function.StringParameterValidatorResponse) {
	if _, err := core.LoadPublicKeyFromData([]byte(req.Value.ValueString())); err != nil {
		res.Error = function.ConcatFuncErrors(res.Error, function.NewFuncError(fmt.Sprintf("incorrect public key %s", err.Error())))
	}
}

type ProtectionParams struct {
	CreateLimit         types.String `tfsdk:"create_limit"`
	ExpiresIn           types.Int32  `tfsdk:"expires_in"`
	NumUses             types.Int32  `tfsdk:"num_uses"`
	ProviderConstraints types.Set    `tfsdk:"provider_constraints"`
}

func (p *ProtectionParams) Into(c *core.SecondaryProtectionParameters) error {
	if !p.CreateLimit.IsUnknown() && !p.CreateLimit.IsNull() && len(p.CreateLimit.ValueString()) > 0 {
		d, durErr := time.ParseDuration(p.CreateLimit.ValueString())
		if durErr != nil {
			return durErr
		}

		c.CreateLimit = time.Now().Unix() + int64(d.Seconds())
	}

	if !p.ExpiresIn.IsUnknown() && !p.ExpiresIn.IsNull() {
		c.Expiry = time.Now().Add(time.Hour * time.Duration(24*int(p.ExpiresIn.ValueInt32()))).Unix()
	}

	if !p.NumUses.IsUnknown() && !p.NumUses.IsNull() {
		c.NumUses = int(p.NumUses.ValueInt32())
	}

	return nil
}

type FunctionTemplate[TMdl, DestMdl any] struct {
	Name                      string
	Summary                   string
	MarkdownDescription       string
	DataParameter             function.Parameter
	DestinationParameter      function.Parameter
	ConfidentialModelSupplier core.Supplier[TMdl]
	DestinationModelSupplier  core.Supplier[*DestMdl]
	CreatEncryptedMessage     func(confidentialModel TMdl, dest *DestMdl, md core.SecondaryProtectionParameters, pubKey *rsa.PublicKey) (core.EncryptedMessage, error)
}

func (f *FunctionTemplate[TMdl, DestMdl]) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = f.Name
}

func (f *FunctionTemplate[TMdl, DestMdl]) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	funcParams := []function.Parameter{
		f.DataParameter,
	}
	if f.DestinationParameter != nil {
		funcParams = append(funcParams, f.DestinationParameter)
	}

	funcParams = append(funcParams,
		function.ObjectParameter{
			Name:           "content_protection",
			Description:    "Secondary content protection parameters to be embedded into  output ciphertext",
			AllowNullValue: true,

			AttributeTypes: map[string]attr.Type{
				"create_limit": types.StringType,
				"num_uses":     types.Int32Type,
				"expires_in":   types.Int32Type,
				"provider_constraints": types.SetType{
					ElemType: types.StringType,
				},
			},
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
		Summary:             f.Summary,
		MarkdownDescription: f.MarkdownDescription,
		Return:              function.StringReturn{},

		Parameters: funcParams,
	}
}

func (f *FunctionTemplate[TMdl, DestMdl]) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	confidentialModel := f.ConfidentialModelSupplier()
	destinationModel := f.DestinationModelSupplier()
	var headerParams *ProtectionParams
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
		if copyErr := headerParams.Into(&md); copyErr != nil {
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
