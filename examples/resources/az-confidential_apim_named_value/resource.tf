# ----------------------------------------------------------------------------
#
# Azure API Management Named Value Resource
#
# The resource allows importing pre-set named values into an API management
# service. Although the same can be achieved with Key Vault integration, in
# some cases this approach will prove more advantageous owing to the lowered
# churn of Key Vault objects.
#
# ----------------------------------------------------------------------------

resource "az-confidential_apim_named_value" "named_value" {
  content = <<-CIPHERTEXT
            H4sIAAAAAAAA/1TTT/d6SgDH8f08ivbuPYjE95y7SDQoEhplNzHk39CQ6NHf8/vufp/la/HZvf/9M92E
            trfan73I9KJfAXtG8EhOZVuOPytxu5HVjaIoCjDnvmTLH1IVUZJkRQFul5EmIDlhhKbkZ5V2jPDDyEpa
            8JMI/AanpCV03Hd0GBku6Tj8rIDPuqnMCPtLM9J2/4xkGEtagGjpyc8K9+WqxRQXvx88xS3JVhNu3gSA
            zrV7OQ+Vds133lmH85a3OWfzzo8BU1NPuslGRk6WCgMa8X3cO4WYeRw2En/o3kGUA9vk5MZn6hZNTlHC
            ZXGOtEqwFY0M0cSOtQdx5by7a2h9eYsf3DdmcryJ/Is9cYieCJCS4/r+mxVOKyH6vmUS5+hO/jEO2eZx
            CDnBr9x3M56JRpqyOmeTuKC1fqNouqaxWp0BJonPpjC6ake7zWDglQWTteN1mMkax2N+OnH5Yi9rv+L3
            AZZ8qhmXAeNXYG8fJ7dCQECm8zC26Q0xKXX2yJLv0l17XWY9e5Y0IptI8r/YfbbP4k4Ph30PjcrJwngR
            6HKqiQKI9+jhzVBfFx8KtvwJdqe1IcNmJ/iQaruUn+VA0PV2zqV5kNImNZ8YMkny6/F2xRYEfdy2dNtN
            no+912cKt1LRdHOCw63qCqNnndhdVfqE7jgIlbwy1axJM78upHoojughA5URr/uiZRwkXavG3YHT0S0q
            ZpHCSl+q7vPigqBGwnIdIDaLt4ad5alYxE01CfZ1D3bVPk7phZt2uX69P+vaVj/o6N6/UWnVH9Ux9FoY
            Ys7XzfSrrp9cEcR752s06MsT5ShEILkEifHCexoP2HpP+ee0HuxPsVPDjSrk7QZdRPhF5Kp8y+FytS5n
            9RZfxfJQHHqDCUQELBxc6xgRazvvpldqxbxDRREX4lENeU4PE77NWi6pYVP8B34LMz3j7+L+DwAA//+j
            T7ncigMAAA==
            CIPHERTEXT


  tags = [
    # Fill the tags as desired
    # "TagValue"
  ]

  # Confidential values created from the sensitive ciphertext are best kept secret, meaning that
  # these will be hidden on the Portal display
  secret = true

  # A display name of this named value. It doesn't play a role in the actual operation;
  # whereas it's great to give it a descriptive name. If it is not specified, it is
  # inferred from the name of the destination named value.
  # display_name = "confidential named value"

  destination_named_value = {
    # Specify a Azure subscription id where the APIM instance is created
    az_subscription_id = "...specify the subscription..."
    # Specify a Azure resource group  id where the APIM instance is created
    resource_group = "...specify the resource group name..."
    # Specify a Azure APIM service name
    api_management_name = "...specify the APIM service name..."
    # Specify the name this named value should use; may contain
    # only letters, digits, periods, dashes and underscores
    name = "...specify the APIM named value..."
  }
}