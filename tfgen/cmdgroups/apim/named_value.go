package apim

import (
	_ "embed"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	res_apim "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

//go:embed named_value.tmpl
var namedValueTFTemplate string

type TargetCLIParams struct {
	AzSubscriptionId  string
	ResourceGroupName string
	ServiceName       string
}

func (ap *TargetCLIParams) SpecifiesTarget() bool {
	return len(ap.AzSubscriptionId) > 0 && len(ap.ResourceGroupName) > 0 && len(ap.ServiceName) > 0
}

type NamedValueCLIParams struct {
	TargetCLIParams
	inputFile       string
	inputFileBase64 bool

	namedValueName string
}

func (ap *NamedValueCLIParams) SpecifiesTarget() bool {
	return len(ap.namedValueName) > 0 && ap.TargetCLIParams.SpecifiesTarget()
}

func CreateNamedValuedArgParser() (*NamedValueCLIParams, *flag.FlagSet) {
	var nvParms NamedValueCLIParams

	var nvCmd = flag.NewFlagSet("named-value", flag.ExitOnError)

	nvCmd.StringVar(&nvParms.inputFile,
		"named-value-file",
		"",
		"Read named value from specified file")

	nvCmd.BoolVar(&nvParms.inputFileBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	nvCmd.StringVar(&nvParms.AzSubscriptionId,
		AzSubscriptionIdOptionCliOption.String(),
		"",
		"Subscription Id where target APIM service resides")

	nvCmd.StringVar(&nvParms.ResourceGroupName,
		ResourceGroupNameCliOption.String(),
		"",
		"Resource group name where target APIM service resides")

	nvCmd.StringVar(&nvParms.ServiceName,
		ServiceNameCliOption.String(),
		"",
		"APIM service name")

	nvCmd.StringVar(&nvParms.namedValueName,
		NamedValueCliOption.String(),
		"",
		"Named value identifier")

	return &nvParms, nvCmd
}

type BaseCoordinateModel struct {
	AzSubscriptionId  model.TerraformFieldExpression[string]
	ResourceGroupName model.TerraformFieldExpression[string]
	ServiceName       model.TerraformFieldExpression[string]
}

func NewBaseCoordinateModel(azSubscriptionId, resourceGroupName, serviceName string) BaseCoordinateModel {
	rv := BaseCoordinateModel{
		AzSubscriptionId:  model.NewStringTerraformFieldExpression(),
		ResourceGroupName: model.NewStringTerraformFieldExpression(),
		ServiceName:       model.NewStringTerraformFieldExpression(),
	}

	if len(azSubscriptionId) > 0 {
		s := azSubscriptionId
		rv.AzSubscriptionId.SetValue(s)
	}

	if len(resourceGroupName) > 0 {
		s := resourceGroupName
		rv.ResourceGroupName.SetValue(s)
	}

	if len(serviceName) > 0 {
		s := serviceName
		rv.ServiceName.SetValue(s)
	}

	return rv
}

type NamedValueCoordinateModel struct {
	BaseCoordinateModel
	NamedValue model.TerraformFieldExpression[string]
}

func NewNamedValueCoordinateModel(azSubscriptionId, resourceGroupName, serviceName, namedValue string) NamedValueCoordinateModel {
	rv := NamedValueCoordinateModel{
		BaseCoordinateModel: NewBaseCoordinateModel(azSubscriptionId, resourceGroupName, serviceName),
		NamedValue:          model.NewStringTerraformFieldExpression(),
	}

	if len(namedValue) > 0 {
		s := namedValue
		rv.NamedValue.SetValue(s)
	}

	return rv
}

type NamedValueTerraformCodeModel struct {
	model.BaseTerraformCodeModel
	Tags model.KeylessTagsModel

	DestinationNamedValue NamedValueCoordinateModel
}

func MakeNamedValueGenerator(kwp *model.ContentWrappingParams, args []string) (model.SubCommandExecution, error) {
	namedValueParams, namedValueCmd := CreateNamedValuedArgParser()

	if parseErr := namedValueCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	if kwp.LockPlacement && !namedValueParams.SpecifiesTarget() {
		return nil, fmt.Errorf(
			"options %s, %s, %s, and %s must be supplied where ciphertext is labelled with its intended destination",
			AzSubscriptionIdOptionCliOption,
			ResourceGroupNameCliOption,
			ServiceNameCliOption,
			NamedValueCliOption,
		)
	}

	mdl := NamedValueTerraformCodeModel{
		BaseTerraformCodeModel: model.NewBaseTerraformCodeModel(kwp, "named_value", "api management named value", "destination_named_value"),

		Tags: model.KeylessTagsModel{
			IncludeTags: true,
		},

		DestinationNamedValue: NewNamedValueCoordinateModel(
			namedValueParams.AzSubscriptionId,
			namedValueParams.ResourceGroupName,
			namedValueParams.ServiceName,
			namedValueParams.namedValueName,
		),
	}

	return func(inputReader model.InputReader) (model.TerraformCode, core.EncryptedMessage, error) {

		namedValue, readErr := inputReader(NamedValueContentPrompt,
			namedValueParams.inputFile,
			namedValueParams.inputFileBase64,
			false)

		if readErr != nil {
			return "", core.EncryptedMessage{}, readErr
		}

		return OutputNamedValueTerraformCode(mdl, kwp, string(namedValue))
	}, nil

}

func OutputNamedValueTerraformCode(mdl NamedValueTerraformCodeModel, kwp *model.ContentWrappingParams, namedValueDataAsStr string) (model.TerraformCode, core.EncryptedMessage, error) {
	em, params, err := makeNamedValueEncryptedMessage(mdl, kwp, namedValueDataAsStr)
	if err != nil {
		return "", em, err
	}

	mdl.EncryptedContent.SetValue(model.Ciphertext(em.ToBase64PEM()))
	mdl.EncryptedContentMetadata = kwp.GetMetadataForTerraformFor(params, "api management named value", "destination_named_value")
	mdl.EncryptedContentMetadata.ResourceHasDestination = true

	tfCode, tfCodeErr := model.Render("apim/namedValue", namedValueTFTemplate, &mdl)
	return tfCode, em, tfCodeErr
}

func makeNamedValueEncryptedMessage(mdl NamedValueTerraformCodeModel, kwp *model.ContentWrappingParams, namedValueDataAsStr string) (core.EncryptedMessage, core.SecondaryProtectionParameters, error) {
	publicKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return core.EncryptedMessage{}, kwp.SecondaryProtectionParameters, rsaKeyErr
	}

	var lockCoord *res_apim.DestinationNamedValueModel
	if kwp.LockPlacement {
		lockCoord = &res_apim.DestinationNamedValueModel{
			DestinationApiManagement: res_apim.DestinationApiManagement{
				AzSubscriptionId: types.StringValue(mdl.DestinationNamedValue.AzSubscriptionId.Value),
				ResourceGroup:    types.StringValue(mdl.DestinationNamedValue.ResourceGroupName.Value),
				ServiceName:      types.StringValue(mdl.DestinationNamedValue.ServiceName.Value),
			},
			Name: types.StringValue(mdl.DestinationNamedValue.NamedValue.Value),
		}
	}

	em, md, emErr := res_apim.CreateNamedValueEncryptedMessage(namedValueDataAsStr, lockCoord, kwp.SecondaryProtectionParameters, publicKey)
	return em, md, emErr
}
