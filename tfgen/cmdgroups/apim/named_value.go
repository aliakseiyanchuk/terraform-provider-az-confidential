package apim

import (
	_ "embed"
	"errors"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	res_apim "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

//go:embed named_value.tmpl
var namedValueTFTemplate string

type TargetCLIParams struct {
	subscriptionId    string
	resourceGroupName string
	serviceName       string
}

func (ap *TargetCLIParams) SpecifiesTarget() bool {
	return len(ap.subscriptionId) > 0 && len(ap.resourceGroupName) > 0 && len(ap.serviceName) > 0
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

	var nvCmd = flag.NewFlagSet("named-value", flag.ContinueOnError)

	nvCmd.StringVar(&nvParms.inputFile,
		"named-value-file",
		"",
		"Read named value from specified file")

	nvCmd.BoolVar(&nvParms.inputFileBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	nvCmd.StringVar(&nvParms.subscriptionId,
		"az-subscription-id",
		"",
		"Subscription Id where target APIM service resides")

	nvCmd.StringVar(&nvParms.resourceGroupName,
		"resource-group-name",
		"",
		"Resource group name where target APIM service resides")

	nvCmd.StringVar(&nvParms.serviceName,
		"service-name",
		"",
		"APIM service name")

	nvCmd.StringVar(&nvParms.namedValueName,
		"named-value",
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
		rv.AzSubscriptionId.SetValue(&s)
	}

	if len(resourceGroupName) > 0 {
		s := resourceGroupName
		rv.ResourceGroupName.SetValue(&s)
	}

	if len(serviceName) > 0 {
		s := serviceName
		rv.ServiceName.SetValue(&s)
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
		rv.NamedValue.SetValue(&s)
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

	if kwp.AddTargetLabel {
		if !namedValueParams.SpecifiesTarget() {
			return nil, errors.New("options -az-subscription-id, -resource-group-name, -service-name, and -named-value must be supplied where ciphertext is labelled with its intended destination")
		} else {
			kwp.AddLabel(res_apim.GetDestinationNamedValueLabel(
				namedValueParams.subscriptionId,
				namedValueParams.resourceGroupName,
				namedValueParams.serviceName,
				namedValueParams.namedValueName,
			))
		}
	}

	mdl := NamedValueTerraformCodeModel{
		BaseTerraformCodeModel: model.BaseTerraformCodeModel{
			TFBlockName:           "named_value",
			CiphertextLabels:      kwp.GetLabels(),
			WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		},

		Tags: model.KeylessTagsModel{
			IncludeTags: false,
		},

		DestinationNamedValue: NewNamedValueCoordinateModel(
			namedValueParams.subscriptionId,
			namedValueParams.resourceGroupName,
			namedValueParams.serviceName,
			namedValueParams.namedValueName,
		),
	}

	return func(kwp model.ContentWrappingParams, inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		namedValue, readErr := inputReader("Enter named value data",
			namedValueParams.inputFile,
			namedValueParams.inputFileBase64,
			false)

		if readErr != nil {
			return "", readErr
		}

		namedValueAsStr := string(namedValue)

		if onlyCiphertext {
			return OutputNamedValueEncryptedContent(kwp, namedValueAsStr)

		} else {
			return OutputNamedValueTerraformCode(mdl, kwp, namedValueAsStr)
		}

	}, nil

}

func OutputNamedValueTerraformCode(mdl NamedValueTerraformCodeModel, kwp model.ContentWrappingParams, namedValueDataAsStr string) (string, error) {
	s, err := OutputNamedValueEncryptedContent(kwp, namedValueDataAsStr)
	if err != nil {
		return s, err
	}

	mdl.EncryptedContent.SetValue(&s)
	return model.Render("apim/namedValue", namedValueTFTemplate, mdl)
}

func OutputNamedValueEncryptedContent(kwp model.ContentWrappingParams, secretText string) (string, error) {
	helper := core.NewVersionedStringConfidentialDataHelper()
	_ = helper.CreateConfidentialStringData(secretText, res_apim.NamedValueObjectType, kwp.GetLabels())
	em, err := helper.ToEncryptedMessage(kwp.LoadedRsaPublicKey)
	if err != nil {
		return "", err
	}

	return em.ToBase64PEM(), nil
}
