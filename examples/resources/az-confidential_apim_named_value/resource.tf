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
            H4sIAAAAAAAA/1SUzZKyOBRA9zyFe8YJKL9dNQtQUbH5EVGRXQgBoxAiBBSefqq7pmrqu8uzOPfezZn/
            jL3Z7v3ZKvDjjR//EmHVYsjxN6kJ/5rJuqoYqibrprD5MNKOv0jVDOUHeU2OqwgXuMUU4a8ZaloMOt4S
            WoJBFsIKIlxjylcN7XgLCeXd1wxOczSvYIarLwBA12cdagnjpKEdkExdRTo05lmRZXMFmWieqcpiruaG
            uVigLC9kDFrcNX2L8LZtetYB1NCC5JhyAqv5cwCsbQaS47YDHkFt0zUF/9tixIMUlr/XgA63A0EYQIQw
            45AiDCiscX6BVY+7Hxzjjlt9KUtC+J/tjxdyXDd/cdxxQkshHhn+mkFGZvX/K359s+FHKAhhQEGWyOKT
            niTv0HuQSnHmcj+VOzUekzMyS0pkz1+la2d/ilrWX7/Dl3bUm+vtbaSK8C2uDo8eHZqPpvQVi26D1C5N
            zf9YncSS6ciDy90Y0o09jEMPxZOtqvlZgutKT+Sjjybheve2S3GzVNsiMBJKr+ndWGQSqN/GdMvydKks
            ApkswwRWmqIfSJQbSTzpD9kp1VW3rYVQrOEaDW4QlvxMkB5IO9FR0PfdvNVe6Ei2fG70GysG586yfepy
            L3uihm7WblHzCfsC91fucQL5WT266BLxz95/mR/dbQ+VTG44d1ZnhzQmHXV7z/ra5QBcgvayTOxk7Zea
            LFxhxI9VZRzp4VVaU2Ktpepk7d0xcGtQANfwp+UxNpVvVXROahJtXo+3JFoXLVOeoRXbwvGjvT+sOEWf
            BdU+nZ7gqL9hSYMntUlQGPV27E7pZ3VZ7arJFYdXQrRYVmKgHSAbx4ewhGq0FVdaWY5deCj8FExJCmDi
            LJzKToKTruB1u3ShrybpatykgTc9lldflkGxLWVfEvA2kJ/B3SOP8/J2vBmNOdU5Gz6vi2HbH0VlJy1f
            vMOTaheEdT1UNuiYs7PtRzV7vcVSsEhcnOT0LSNzl0uWFb0iR7tngbnjUF+z4WBcxHIn6fsXtZr4MnH9
            Yu1H++QdesXZrjdC0aXOK77S8DwuzO/mGVk7ZrIzGh+jOCxDb0ezHcgu/C4q/wi/Odj46z/z8G8AAAD/
            /zsyfw03BAAA
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