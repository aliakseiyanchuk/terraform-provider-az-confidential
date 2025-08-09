# ----------------------------------------------------------------------------
#
# Azure KeyVault Secret
#
# The resource creates a secret version in the specified Key Vault service.
# Secret version in Key Vault are immutable, their value cannot be changed
# after these were created. To update a secret, create a new version
# and delete the one previously created.
# ----------------------------------------------------------------------------

resource "az-confidential_keyvault_secret" "secret" {
  content = <<-CIPHERTEXT
       H4sIAAAAAAAA/1TTyZKqSACF4T1P4Z7uYBazInqBiBTIoJgy7RASTIZkygLx6Tvq7u6Js/r2/7+/Oxqm
       5e1034OGB/8Io08oo8jBHaZfO0FVFF6QRIVnjPeAp+2XDnsR8LzCM25foDZAJZoQydHXLu8nxM10wqTi
       FoG5tlmOOkSo3pOZThkmdP7aMdepX3CBpr+0QF3/D0UzxaRi4Dagr12zcDPKJ0QZxtPd/hnZ8/edVObN
       D/itO7JXbttnn+vbvTf2XomsQisVbFRgzV+SpsFh4DTN5V/wMrkMebDHvT+ocnnLG8C9QQQEDWh7/6b7
       rcF6VTCy47pVaFw8eCws0MfrsHdwm+RjEPgmcw79932AE/dap/gcsyjlrZJaochaTp3Vz013YdKeIzYL
       PVr39+8qw79XThfVDB4rY8s9dQAom0w3YaRaZnTpQsCGWtE7Hi8AWD6K9FKQKn2PJ5h8MrQMef5Jm6vd
       dVhoGNFJ2u1ceT78WaCoDPdoEip4A9b9+3NJ3W/g4BmPokfyrRttjqxQwh59znWmA7zqKnPlME54CxUP
       a2naALAkpGuftLxZs7Gy8oJQyPpIkmcRlbNZNs3Pdea0jo55/FgrkWfMYwWflqyUoRnjOmmMUDrEoL9U
       QPn0KtZrHHJiZURhfoteJzZ6J4KgRdns195n2XTINFzTqzdVwD/Pgz+4m5iSPqpC54W14G7LaWW552M+
       8nF4YD/aa4l1ftRy6nfu+6PeTgtjBHCE4DDq2+GyOvhs0ET7OGmtaJbYOJIiE2IfU2xcRTlBLX3dTdUL
       pbZpXOi+XvOJwdcCFHa1xQ/XaVonBOz9EiT+SddkXctp5tiGQ55tIpkXqQdLvP2UZa0oBkw5gXQ5Ydre
       hfYNmhmfG5rUB6iQJ2mR6+xUKsCuZI1jgUyW3D0d/mP+BGV4p78D+z8AAP//IsFRdHkDAAA=
       CIPHERTEXT

  # This secret is enabled for operation. Optionally, there is an option
  # to temporarily disable it.
  enabled = true

  # If the secret version should nto used before a specific date,
  # it needs to be formatted yyyy-mm-ddTHH:MM:SS'Z'
  # not_before_date = "2025-08-09T15:40:50Z"

  # If the secret version cannot be used after this date
  # it needs to be formatted yyyy-mm-dd'T'HH:MM:SS'Z'
  # not_after_date = "2026-08-09T15:40:50Z"

  tags = {
    # Fill the tags as desired
    # tagName = "TagValue"
  }

  destination_secret = {
    vault_name = "demo-vault"
    name = "demo"
  }
}