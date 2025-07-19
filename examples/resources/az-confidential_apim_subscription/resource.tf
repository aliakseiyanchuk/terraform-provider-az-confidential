resource "az-confidential_apim_subscription" "subscription" {
  content = "H4sIAAAAAAAA/1TSuba6OACA8Z6nmD5nDkvYLKYQiFy2AAoIdBFuQARZFIU8/Zz5d/OVX/37+78MZDv4LzPECcLJn8M1c6QwyQ2agVTuKywnqClijq/vw7Kc5Saa6uHw25TPBuZRIYEiVbZkUJEw8J1Fx/TNKQNvmyxw23HpIhL0Qi0kF7xIYDHg2yHNd8zTvu5smDgf6ykO0qGFBIH+ic05psLKMeNXFIDqz5dRe7k2lM37PGkv0Ms6HGqqhLukZFfLts8l0Au8yfoVkNt4mtRHztz5wV1CzyzgyNuXdU6KFH4VeK+/xg2bpczKTOZjk62ATErr9rGmm7TrRnbVI0JSdVoHnQvaRrWzDQ4ihmizwEcmvtjoWwiGTyIW7+RcrcUE9jz2vM1/KL+IGi8CCu0pzG3d5JyZ3JvdfdDXkJ2Cw1yM+1LqkSlpH3OkUO6O6V26h6mHPVfPhF7x8HGnBHjVxtqhrB/c070APkP2kUq9Pzm5da+Z9QpL6jrpfspTJ4g7xYRhYrba8tmM4xklKLB833+WxQsvXBULHxbW9GT2okDk1L7WtJQTno4kf0W3YLF++uDePbFWMP+mHzuG6kjNxt+0wUvy2DhIQi+ll5bvhfitQOehMprwlep4/pZSTd7LH8lzID7KrhF3YIkc/dwg1hxiCTm7tHLz7fz+8mQMrJDOE0n86kn7UfZKookLjD5lPYtrdSrw5Vyh9SuM/o9asuYNesjii5ZyOzYefkFvgZWB1WivMsKkQUMUK3gDI8vD63yyx77IKvQP9wcvwtb/Mf8bAAD//55aK1blAgAA"
  display_name = "confidentialSubscription"
  state = "active"
  allow_tracing = false

  # A display name of this named value. It doesn't play a role in the actual operation;
  # whereas it's great to give it a descriptive name. If it is not specified, it is
  # inferred from the name of the destination named value.
  # display_name = "confidential named value"

  destination_subscription = {
    # Specify a Azure resource group  id where the APIM instance is created
    resource_group = var.az_apim_group_name
    # Specify a Azure APIM service name
    api_management_name = var.az_apim_service_name
    # Specify the identifier for this subscription
    # subscription_id = "...specify the APIM subscription id..."
    # Specify the API product
    product_id = "productId"
    # Specify the API this subscription will be bound with
    # api_id = "...specify the API this subscription will be associated with..."
    # Specify the API this subscription will be bound with
    # user_id = "...specify the user Id "
  }
}
