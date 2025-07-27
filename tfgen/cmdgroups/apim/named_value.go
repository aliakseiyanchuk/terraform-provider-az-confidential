package apim

import (
	_ "embed"
	"errors"
	"flag"
	res_apim "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"strings"
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
		"az-subscription-id",
		"",
		"Subscription Id where target APIM service resides")

	nvCmd.StringVar(&nvParms.ResourceGroupName,
		"resource-group-name",
		"",
		"Resource group name where target APIM service resides")

	nvCmd.StringVar(&nvParms.ServiceName,
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
		return nil, errors.New("options -az-subscription-id, -resource-group-name, -service-name, and -named-value must be supplied where ciphertext is labelled with its intended destination")
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

	return func(inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		namedValue, readErr := inputReader("Enter named value data",
			namedValueParams.inputFile,
			namedValueParams.inputFileBase64,
			false)

		if readErr != nil {
			return "", readErr
		}

		namedValueAsStr := string(namedValue)

		if onlyCiphertext {
			publicKey, rsaKeyErr := kwp.LoadRsaPublicKey()
			if rsaKeyErr != nil {
				return "", rsaKeyErr
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

			em, emErr := res_apim.CreateNamedValueEncryptedMessage(namedValueAsStr, lockCoord, kwp.SecondaryProtectionParameters, publicKey)
			if emErr != nil {
				return "", emErr
			}

			fld := model.FoldString(em.ToBase64PEM(), 80)
			return strings.Join(fld, "\n"), nil

		} else {
			return OutputNamedValueTerraformCode(mdl, kwp, namedValueAsStr)
		}

	}, nil

}

func OutputNamedValueTerraformCode(mdl NamedValueTerraformCodeModel, kwp *model.ContentWrappingParams, namedValueDataAsStr string) (string, error) {
	publicKey, rsaKeyErr := kwp.LoadRsaPublicKey()
	if rsaKeyErr != nil {
		return "", rsaKeyErr
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

	em, emErr := res_apim.CreateNamedValueEncryptedMessage(namedValueDataAsStr, lockCoord, kwp.SecondaryProtectionParameters, publicKey)
	if emErr != nil {
		return "", emErr
	}

	mdl.EncryptedContent.SetValue(em.ToBase64PEM())
	mdl.EncryptedContentMetadata = kwp.GetMetadataForTerraform("api management named value", "destination_named_value")
	return model.Render("apim/namedValue", namedValueTFTemplate, &mdl)
}
