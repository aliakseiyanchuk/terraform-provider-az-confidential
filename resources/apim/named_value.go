package apim

import "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"

type NamedValueModel struct {
	resources.ConfidentialMaterialModel

	DestinationAPIM DestinationCoordinates `tfsdk:"destination_named_value"`
}

type NamedValueSubscriptionSpecializer struct {
}
