package apim

type DestinationCoordinates struct {
	ResourceGroup string
	ServiceName   string
}

type DestinationSubscriptionCoordinateModel struct {
	DestinationCoordinates
}
