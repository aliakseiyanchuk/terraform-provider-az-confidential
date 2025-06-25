# Copyright (c) HashiCorp, Inc.

resource "az-confidential_secret" "conf_secret" {
  content = "H4sIAAAAAAAA/1TSu9ZzSgCA4d5V7D5rL0SCKXYxDmGcxjFCFyQEI3zOrn6v/+v+t3zr598/SaqGnH9k7ISqE/4e6vtjJxytnkrFnV/k+mW/ZcY8hc3IM6YINNwxowSYR+oSbZ+v+blqEyni2rptwZuHOKLGRxBfs+Ded/ogQtptYgJBgvL7ZK+Of/F5fIT6APs3/4nK3DbW2NcM5jL1kdQGWAuo+zqbzvuO2iIZt4oWOIetvsJX0m9p7nMzSrdccOGgkkW0UK9yah7Nu4d8e31wjSK6VOpWtvWyDc9FWmZgtj5SSLchZ266Fetszj+Tag3NvAUMCJeT0tN7oMhkgrR0iZhmpeAz14x7UhivoSand7pPkVQ1ZehnKxPRMVDoUiggW6dnHE+7aa0W2rkjP/RdtSOseFTuHEnaHeCiHue5n4eZmLtCIulO+Gp+mGOXIGtKPqf+MhiXXcNissxMwt7Eop+04hipA5SlvXcF6YG3VE/+SrYbP86PqKEnw4VFWxvC2EwEZVkTBvK2d33mnc1hv0o/b2bnKHqoOXR11yUzP6+QJ50kHg9dqSfvYo+dqVmVzIzdIpzxMJYrZk5Fq1eyjELfkkElPqnGjR/qaL3kOBegIsWHZpsfz/bGp9Yo9AkKT3p8qwfmdUgaHPsWS6CmhaLakPmtdy5lEfxjqlrxABDKQ1YtEgB0V6VRJyq7MdMw8UOjiXGC2NurNGg88OyMIlsQRNcehxs17psVd4MasPXhO975+t4Glf88TQSCAoTRsrRHBFjSOug/6hev6ih/Y/4/AAD//wjliNPlAgAA"

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  # The secret version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-06-14T20:56:08Z"

  # The secret version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-06-14T20:56:08Z"

  tags = {
    # Fill the tags as desired
    # tagName =  "TagValue"
  }

  destination_secret = {
    name = "example-secret-3"
  }
}
