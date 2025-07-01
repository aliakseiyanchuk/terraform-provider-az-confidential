# Copyright (c) HashiCorp, Inc.

resource "az-confidential_secret" "conf_secret" {
  content = "H4sIAAAAAAAA/1TStxaySABA4Z6n2J6zx4CoFFvAEIUBJAxIN0MUYUgi4en37N/tLW/9/f1fkqIZ9l/AsQPFDv4cph7NIBvNoDgtpm8DVaGIQw88f3/7HYvr2SD87gutPMpCL9i4Jewtvo3aR1MO4aycCmady6p7W4RfngLIXKuPLyabPofIvd3bZsBC9RQ0lvrjELFogSt2qXKKgvV8DYitRBMje1IBEnFDcJRpnYiAU/fuXZJVm90FQQXYHnaqpe9eDz80JyOwaP4NwOsKiVc9bj4TzdVLarQxQ8Ph6mbk/YF9GYuA6vshbqu38Wp2LEnqxslm+WN741zwW20F0kdQ90+5MMW23yCFc2R1g1FAL5O5NLE73M7yhNqEqG27isI5IduL1GuT6tnaaVw3/azjBT41wnRwItHxikp+W+bhoFYAN79qYxFLcEXEGHacLt1RyQ/9kmm8quvXZ1PmSXl4XiawTkzIybJgGwcnGetUi4DZNx/heR+XWKJGbFup7Xfg3F5m/spx0t0x2Fyqad5f9La29aPEBI7khjH6NF3PpxkIC4+NH3rZu54HNL8N8m/yHlKPGIF+V/OLc/L6qQjN7RZ3p1UiI5P+FAzlVbBpa+cv5XBdvQg5Lx6ufSviGpZZc9yrrjX1vL1k2nJcw6+CEaWyNAjQnpj85s+utMEwTqYtxcHqBUcro9CTL2nt33pz2HbQ941Ihg6omq9HNGmSH9qP7vucOZixzmb18TwYPs4bnstapYhQtXrvMzFQp7nDz3mp3zESgfgP8wevYsv/x/xvAAAA///TFelf5QIAAA=="

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
    addedTag = "AddedValue"
    addedTag1 = "AddedValue2"
  }

  destination_secret = {
    name = "example-secret-3b"
  }
}
