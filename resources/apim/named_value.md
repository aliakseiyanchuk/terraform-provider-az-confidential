Creates a named value in API Management without revealing its value in state.

This resource fills in a gap where a named value is sensitive enough to be avoided being stored
in the Terraform configuration in the clear yet not sensitive enough to be placed in the key vault.

An example of such a scenario is a shared code repository containing routing configuration
belonging to different teams. The purpose of adding this protection here would be to allow the
teams to collaborate without exposing routing internals. Adopting this resource can help avoiding
a churn of secrets in Key Vault.