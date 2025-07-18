resource "az-confidential_apim_named_value" "named_value" {
  content = "H4sIAAAAAAAA/1TSubKySABA4ZynmJyagqZtwWAClE3AZrPZMhYvy0Ww2fHpp+bP5oQn/v7+r6uq3/FfNwc/Vfz8c5hX154VdYqgF19Xh1aonLQKeF9ir0ET1m3U1xOS8mrRRNDIK5WhCiJ+o/ohadZ41ExH1tDpo1cWkkiB4vtnujQBG4YFdhXjTMrzYYmv+nFS1126stkId3cJZ2ESzHio6RMxCvvhIGchnpZxPNBGIplV0Mewl66vJc+iWPQ5hsHcwR17pS7OwA9o+KaXLrv/pm7JlIqxGZPX5JapIQKIkao3JDu2bEySNkfNwA1Dj6r2GbbhACbDirs4eqtfYBp2isDCWDAoFm7IoaCOW5qurNq9yNsVs+PiOoW8E1I+wO02jrJdSFx4sSvs0Vx/VNlPIQZIY/j+PFx5Wpgghz881RAWPwfy2QBVCaewBavDEwq60CW3+p1jEx8kq59IGGt/e53qnkmAavQOAQYqMOki/Nol6bc7NdPeA1e9faRmNKOpqRc8zV8IPnyT23W75vElS1ZasIyVIXmW5lMRsym3HvI2Ot4vv8ErGgx+2zOeYG9c8hrWzmpLzpPch5telNE5db06iDBjCOLQORnKT2vbl4KZfzytqZL5zr0PO2/vc4HJ79yKZkgR9LkKLU3GbpdH6yb13MaUiRJ/CHRuilNRpyzKcjP2twSB6wiS3e+vROuqBr/ybylk6WBfPkbwYz6iFaU+urqswOiSa02WxDskf8i9UsLRl90vWcDtOH9UqT+/3kJp3L2n4v3D/MGrYuX/mP8NAAD//0INKgvlAgAA"
  tags = [
    # Fill the tags as desired
    # "TagValue"
    "dev",
    "acceptance"
  ]

  # Confidential values created from the sensitive ciphertext are best kept secret, meaning that
  # these will be hidden on the Portal display
  secret = true

  # A display name of this named value. It doesn't play a role in the actual operation;
  # whereas it's great to give it a descriptive name.
  display_name = "cfNamedVal23-t"

  destination_named_value = {
    # Specify a Azure subscription id where the APIM instance is created
    az_subscription_id = var.az_subscription_id
    # Specify a Azure resource group  id where the APIM instance is created
    resource_group = var.az_apim_group_name
    # Specify a Azure APIM service name
    api_management_name = var.az_apim_service_name
    # Specify the name this named value should use
    name = "exampleNamedValue"
  }
}
