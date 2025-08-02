package apim

import (
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/tfgen/model"
)

const (
	AzSubscriptionIdOptionCliOption model.CLIOption = "az-subscription-id"
	ResourceGroupNameCliOption      model.CLIOption = "resource-group-name"
	ServiceNameCliOption            model.CLIOption = "service-name"
	NamedValueCliOption             model.CLIOption = "named-value"
	SubscriptionIdCliOption         model.CLIOption = "subscription-id"
	ApiIdCliOption                  model.CLIOption = "api"
	ProductIdCliOption              model.CLIOption = "product"
	OwnerIdCliOption                model.CLIOption = "owner"
)

const (
	NamedValueContentPrompt = "Enter named value data"

	SubscriptionPrimaryKeyPrompt   = "Enter primary subscription key"
	SubscriptionSecondaryKeyPrompt = "Enter secondary subscription key"
)

const (
	NamedValueCommand   = "named_value"
	SubscriptionCommand = "subscription"
)
