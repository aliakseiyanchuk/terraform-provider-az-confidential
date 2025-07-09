package apim

import "github.com/aliakseiyanchuk/terraform-provider-az-confidential/resources"

type SubscriptionModel struct {
	resources.ConfidentialMaterialModel

	DestinationSubscription DestinationCoordinates `tfsdk:"destination_named_value"`
}
