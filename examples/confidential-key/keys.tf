resource "az-confidential_key" "confidential_key" {
  content = "ol1+9tlZU+a6KEfHDPd/l4aSckVA1CmXs1clLVIazzKOSUu8qGa4Dg1NcUX1Du+iiCDzGCpSh+Vaaw7mXArGWFogq6FVhiAM8eLM862Lyog+8WoEiOLSggkuvr0TD0y3shRt8Se+rwzBm2/mDNbW+S2pBfqUmbDbX5YUctFXQxVxZiV4svXLBvIvee7JQYPTfnGekAXqSnxt5h1fCteybdz/pLZgsgtlUKPCMAUS4LYlhOmWB5fx9g11SF2qtNnC/1bLKIxAzibqjZa4uTd6+bHdSejiGkytTwsPijh52UD8etrAymNchHWpsiERh+BQqapjSdkH90esmHV9V+EI8TdkErFJRIMGqVGp/wxbIWHG99nTpaQz6cBo7DQf9x8Y9nOcwPFbHgAVjTpOisxwMjUQfJzPb96R7OkScCFxSZ9D1D8HyDoGWbR4d8F1C8Oci7AEAfWkVKREaCeZIbJoeBll4EAJPvICOvqfpp2YXpN572pTgOrFQGUd3R69oF4lII2/zdUDS4qoq/rkNa0IPVCHaBFZI6ACg2TUXERJiTOZOHPfwWkEw/e2PsCv+sXH9yNzRu5rJTcS0felOKPX+42+38n07HtWCmVb30I5bVNBsmqB1w6LI4uWVxEk+TiXAMtyaFQJfPpm5EQ3fwfiijBQDsdS6V6LPhdeHOWUh1g="

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  key_opts = toset([
    "decrypt",
    "encrypt",
    "import",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey"
  ])

  # The secret version cannot be used before this date
  # Needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-06-08T18:40:26Z"

  # The secret version cannot be used after this date
  # Needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-06-08T18:40:26Z"

  tags = {
    # Fill the tags as desired
    # tagName =  "TagValue"
    env = "demo"
  }

  destination_key = {
    vault_name = "lspwd2-d-confidential-kv"
    name = "importedkeyv1"
  }
}
