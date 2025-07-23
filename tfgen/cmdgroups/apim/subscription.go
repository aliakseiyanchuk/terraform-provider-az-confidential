package apim

import (
	_ "embed"
	"errors"
	"flag"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	res_apim "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources/apim"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

//go:embed subscrription.tmpl
var subscriptionTerraformTemplate string

type SubscriptionCLIParams struct {
	TargetCLIParams
	primaryKeyFile   string
	secondaryKeyFile string

	apiScope     string
	productScope string
	owner        string

	subscriptionId string
}

func (ap *SubscriptionCLIParams) SpecifiesTarget() bool {
	return ap.TargetCLIParams.SpecifiesTarget()
}

type DestinationSubscriptionModel struct {
	BaseCoordinateModel
	SubscriptionId model.TerraformFieldExpression[string]
	ProductId      model.TerraformFieldExpression[string]
	ApiId          model.TerraformFieldExpression[string]
	UserId         model.TerraformFieldExpression[string]
}

type SubscriptionTerraformCodeModel struct {
	model.BaseTerraformCodeModel
	State        model.TerraformFieldExpression[string]
	AllowTracing model.TerraformFieldExpression[bool]
	DisplayName  model.TerraformFieldExpression[string]

	DestinationSubscription DestinationSubscriptionModel
}

func NewSubscriptionCoordinateModel(azSubscriptionId, resourceGroupName, serviceName, subscriptionId, productId, apiId, userId string) DestinationSubscriptionModel {
	rv := DestinationSubscriptionModel{
		BaseCoordinateModel: NewBaseCoordinateModel(azSubscriptionId, resourceGroupName, serviceName),
		SubscriptionId:      model.NewStringTerraformFieldExpression(),
		ProductId:           model.NewStringTerraformFieldExpression(),
		ApiId:               model.NewStringTerraformFieldExpression(),
		UserId:              model.NewStringTerraformFieldExpression(),
	}

	if len(subscriptionId) > 0 {
		rv.SubscriptionId.SetValue(subscriptionId)
	}
	if len(productId) > 0 {
		rv.ProductId.SetValue(productId)
	}
	if len(apiId) > 0 {
		rv.ApiId.SetValue(apiId)
	}
	if len(userId) > 0 {
		rv.UserId.SetValue(userId)
	}

	return rv
}

func CreateSubscriptionArgParser() (*SubscriptionCLIParams, *flag.FlagSet) {
	var nvParms SubscriptionCLIParams

	var nvCmd = flag.NewFlagSet("subscription", flag.ExitOnError)

	nvCmd.StringVar(&nvParms.primaryKeyFile,
		"primary-key-file",
		"",
		"Read the primary subscription key from the specified file")

	nvCmd.StringVar(&nvParms.secondaryKeyFile,
		"secondary-key-file",
		"",
		"Read the primary subscription key from the specified file")

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

	nvCmd.StringVar(&nvParms.subscriptionId,
		"subscription-id",
		"",
		"Subscription Id")

	nvCmd.StringVar(&nvParms.apiScope,
		"api",
		"",
		"Scope the subscription to the specified API")

	nvCmd.StringVar(&nvParms.apiScope,
		"product",
		"",
		"Scope the subscription to the specified product")

	nvCmd.StringVar(&nvParms.apiScope,
		"owner",
		"",
		"Associate the subscription with the specified used")

	return &nvParms, nvCmd
}

func MakeSubscriptionGenerator(kwp *model.ContentWrappingParams, args []string) (model.SubCommandExecution, error) {
	subscriptionParam, subscriptionCmd := CreateSubscriptionArgParser()

	if parseErr := subscriptionCmd.Parse(args); parseErr != nil {
		return nil, parseErr
	}

	if kwp.LockPlacement {
		if !subscriptionParam.SpecifiesTarget() {
			return nil, errors.New("at least options -az-subscription-id, -resource-group-name, and -service-name must be supplied where ciphertext is labelled with its intended destination")
		} else {
			kwp.AddPlacementConstraints(core.PlacementConstraint(res_apim.GetDestinationSubscriptionLabel(
				subscriptionParam.AzSubscriptionId,
				subscriptionParam.ResourceGroupName,
				subscriptionParam.ServiceName,
				subscriptionParam.subscriptionId,
				subscriptionParam.apiScope,
				subscriptionParam.productScope,
				subscriptionParam.owner,
			)))
		}
	}

	mdl := SubscriptionTerraformCodeModel{
		BaseTerraformCodeModel: model.NewBaseTerraformCodeModel(kwp, "subscription", "api management subscription", "destination_subscription"),

		DisplayName:  model.NewStringTerraformFieldExpressionWithValue("confidentialSubscription"),
		State:        model.NewStringTerraformFieldExpressionWithValue("active"),
		AllowTracing: model.NewBoolTerraformFieldValueExpression(false),

		DestinationSubscription: NewSubscriptionCoordinateModel(
			subscriptionParam.AzSubscriptionId,
			subscriptionParam.ResourceGroupName,
			subscriptionParam.ServiceName,
			subscriptionParam.subscriptionId,
			subscriptionParam.productScope,
			subscriptionParam.apiScope,
			subscriptionParam.owner,
		),
	}

	return func(inputReader model.InputReader, onlyCiphertext bool) (string, error) {
		primaryKey, readErr := inputReader("Enter primary subscription key",
			subscriptionParam.primaryKeyFile,
			false,
			false)

		if readErr != nil {
			return "", readErr
		}

		secondaryKey, readErr := inputReader("Enter secondary subscription key",
			subscriptionParam.secondaryKeyFile,
			false,
			false)

		if readErr != nil {
			return "", readErr
		}

		pkStr := string(primaryKey)
		skStr := string(secondaryKey)

		if pkStr == skStr {
			return "", errors.New("the primary subscription key is the same as the secondary subscription key")
		}

		if onlyCiphertext {
			return OutputSubscriptionEncryptedContent(kwp, pkStr, skStr)

		} else {
			return OutputSubscriptionTerraformCode(mdl, kwp, pkStr, skStr)
		}

	}, nil
}

func OutputSubscriptionTerraformCode(mdl SubscriptionTerraformCodeModel, kwp *model.ContentWrappingParams, primary, secondary string) (string, error) {
	s, err := OutputSubscriptionEncryptedContent(kwp, primary, secondary)
	if err != nil {
		return s, err
	}

	mdl.EncryptedContent.SetValue(s)
	return model.Render("apim/subscription", subscriptionTerraformTemplate, &mdl)
}

func OutputSubscriptionEncryptedContent(kwp *model.ContentWrappingParams, primary, secondary string) (string, error) {
	kwp.ObjectType = res_apim.SubscriptionObjectType

	helper := res_apim.NewConfidentialSubscriptionHelper()
	_ = helper.CreateSubscriptionData(primary, secondary, kwp.VersionedConfidentialMetadata)

	rsaKey, loadErr := kwp.LoadRsaPublicKey()
	if loadErr != nil {
		return "", loadErr
	}

	em, err := helper.ToEncryptedMessage(rsaKey)
	if err != nil {
		return "", err
	}

	return em.ToBase64PEM(), nil
}
