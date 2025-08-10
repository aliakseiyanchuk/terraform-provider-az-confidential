resource "az-confidential_apim_subscription" "subscription" {
  content = <<-CIPHERTEXT
            H4sIAAAAAAAA/3SUTY+6SBfF93yK3vP4gLwIdNKZgA00yIuIqLiZFEWhCFJIVSHy6Sf/nv9iepKpTSW/
            m3vvuWdxFr+eZbte9LaOo70d7b8Jtx4QoCio7zV9f1tqqqIbirgyOHvq6+H1jVRNkn6hEJeo3aEKDaiD
            6P0N9PWfd9CBC7qjjgqEFQQOdU9r3Anjktu2AH5X1rgjdAB1R8n7G5gXcNGCArXvgvCjhwiioalQA/qi
            qIpioUADLgpVkRZqqRuSBIuyWiJhQASzASJ3wKwnAsRdVZeoozVoF80o9AMe6xINRAhrOGCCK/p/s6/D
            f+hEw1hDJAAIUU9BB9G/ZPwB+vrj16CSQfrx+/dKgRE0fHDb3wt+XFWiO/4fRYTW3YXbv/q/3Xn7D3c4
            zvUT6Lj5aJs+DF6xAtl1BuBhE8P1DudLLsmby2rOW6T1VrN64cdOvky1+1xuiufgnCsOrbaYuTNbeoZd
            4i5vH657wMc5OrGTstaYIDraw92JvBpDLL/Obdj7ijm50gOdEx5o3C32KmAvO6nWc5sx/BWdNl+vhEck
            m+XJSjuNxNMtOyRVlk6aX+hsoi5O2wOxSkNe91zCHm1p6ZkMpg4rUzHOe3CxNU+SHteKTMzzmXU0PZBX
            ztdLtAvHwfrYbK2qOEmnPV5ypnzzLkcM4k8ZmGM8FJmYhWbX+uujesJM3lZAq8KsS2IcXM+ddmKi78f+
            UbjcYzPJfU4iU+PxvEifAQyO3kpBu3a/UtZL0RSHqTnPjhYh4Znt9fOGVvzlvh6XgzQpLXPrVV8pnI9K
            218H0c5yAv01htWBN0M1y2n2nLPrhs+omOPac8FSI89Gqs47Q7wXfBUcw85NoxWXXvttlhDLSUNPFm/e
            LLYsxSckO41pjUiXDTclcXbckOt11dQ3f9l4l1ZLnyGgiAYKh3TBCwJaGYk0ig5tguSzCJiwqSJrNW70
            RMXh2O7K25GUa+Vq8rY1CmN7jyxRonVXPDmRQorC50CsfNL6q506G7y/fM1rE3XGuTNNMWj4sjuPX7F6
            G/Uj8/t+sl9qc0tjpchj7ks9pjcX9OkcyEEIolzkGXwcYBV7k2/H29vnYdxtPyVvn3xw35FhR58/I+Sv
            AAAA//8eo3x1WwQAAA==
            CIPHERTEXT

  display_name  = "confidentialSubscription"
  state         = "active"
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
