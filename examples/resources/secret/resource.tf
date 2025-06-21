# Copyright (c) HashiCorp, Inc.

resource "az-confidential_secret" "confidential_secret2" {
  content = "soUnZMZAeGke0Slmw9bb49E0E5vc57mCfAFrRVm92XK4zZK5eolC3iaGmKJg6NYw9zD+T+2m1mCl/2SbB8c1+pRjvS9NpPwJEepmIIkbIKvYr7XgnJCulywqKIqUmKfUKZPEpIt07iD8dKDJus14ZbpmwqmfEyjMDBOTm72xg6WOyVVVtV3C44xZFEDpIFKkARkeR4dXmCxmssb4gQLtuzobvrjAUKVm3p/Rdhy41rXrE1owUcd05+WbSVpVnrmonx3L4GuJrNxLkhppEQuvjoKEDhfZ7JISAxnhAM524HEuM6qT3bX2DKe973+vIqJqqYW3wXkorKXRe2jwSj6hbzrJlPhmiqlGPTz8m8TRB8jJAguSy5May2hOrcaleHijLvIKLJqjXfgPuop9iqdOY8hvsZhZQeVV3zGSyZJ2wg4ZbtD+qdYdpKHxI3lO58VuKB4UFs8jqeyMfljpnLuy4l9BMD1JZEIqna2ues74+JwLYF6WAnlVq3VtKP1Vj14GK2yS/F1xlFZjSr4qNitkaiyyv8wM7Aqsef1XarfGyw2fggx4KyybzuEqO5SXJ63X9d3/mbFl/6gaD9sF3MGkcmsYWXWk2qyoXc4SKaALZYpXQfPxQXKtKezuiQxfpFFMkmI1incbLA9FTPUvvvLk3JMatPIzcnTpbzxlKel0/ug="

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
    name = "example-secret-2"
  }
}