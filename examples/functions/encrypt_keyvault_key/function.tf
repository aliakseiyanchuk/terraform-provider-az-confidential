locals {
  public_key = <<-PUBLIC_KEY
              -----BEGIN PUBLIC KEY-----
              MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx6PaXN8G5yqJc06mB+Ht
              zcHEvg5CXE8K2MgIqLjGGoOJJrxvdyj4ahxn434VVEFwlN0IDRvw4nsZwNOmXtQH
              qNYUHFJTfPVgbywjRPc72/v/81KVaMEDyLBgLKBndcAROYi2HTgp7DtllZGLCOFD
              MH0SwuAlJ/jM/O4YUksWyQRzVaEXYFoZvU48wKUp691Pp30xgAfaDKmXKXk/gJP+
              WqmaCEHLU26xxflOn0Jh50plClxfE5VNygeWNX2qfcHoeuV4AVktUhYMXXbaZar7
              cofVVg/Xb9RIDQtVtFEOBiOKLrDuFKmiJIcQm+SVPxVm32SwSaSJ32Mo68xc0VRZ
              lwWZsU88mgfB0irQGigf1uSgbeyyhP1LqwO9Ko2axz4we86rr87MdV6fXwyLzofD
              UroQkCpX97h6kRpt2Oo+6a6dVMB0i1o39e0+s/x30DyF/NmYfp6OZeZ9ESexNK+I
              rs7AON0qsktMvJrZrwtWJc3dpR62/QOdYsn6Gg3Awz5/mVJmUXUeTlSNUwLXvRcg
              6+0R7h1I9QSsMp2rBrReJic3xzeU48v1Nsx8bThdHhHniJxbQKHLLPTkFPvU1GVQ
              /4+V/CknT5iV3y+hgcLK+RA013P7ZjYApzpVkMfBcUZbKzKOTb++nXzlJrWwCc2b
              kHaPtEkvXVnamkL9RoClPnkCAwEAAQ==
              -----END PUBLIC KEY-----
              PUBLIC_KEY

  plain_private_key = file("${path.module}/ephemeral_private_key.pem")
  plain_ec_private_key = file("${path.module}/private-ec-key-prime256v1.pem")
  plain_der_rsa_private_key = file("${path.module}/ephemeral-rsa-private-key-encrypted.pem")
  # Note: der-encrypted files cannot be read by Terraform directly.
}

output "encrypted_rsa_key" {
  value = provider::az-confidential::encrypt_keyvault_key(
    {
      key = local.plain_private_key,
      password = "",
    },
    {
      vault_name = "vaultname123",
      name =  "keyName123",
    },
    {
      create_limit = "72h"
      expires_in = 200
      num_uses = 10
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}

output "encrypted_ec_key" {
  value = provider::az-confidential::encrypt_keyvault_key(
    {
      key = local.plain_ec_private_key,
      password = "",
    },
    {
      vault_name = "vaultname123",
      name =  "keyName123",
    },
    {
      create_limit = "72h"
      expires_in = 200
      num_uses = 10
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}

output "encrypted_der_rsa_key" {
  value = provider::az-confidential::encrypt_keyvault_key(
    {
      key = local.plain_der_rsa_private_key,
      password = "s1cr3t",
    },
    {
      vault_name = "vaultname123",
      name =  "keyName123",
    },
    {
      create_limit = "72h"
      expires_in = 200
      num_uses = 10
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}