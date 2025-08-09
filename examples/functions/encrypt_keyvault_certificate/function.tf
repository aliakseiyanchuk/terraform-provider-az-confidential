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

  plain_cert   = file("${path.module}/ephemeral-certificate.pem")
  enc_pem_cert = file("${path.module}/ephemeral-certificate-encrypted.pem")
  der_cert     = filebase64("${path.module}/cert.pkcs12", )
}

output "encrypted_plain_certificate" {
  value = provider::az-confidential::encrypt_keyvault_certificate(
    {
      certificate = local.plain_cert,
      password    = "",
    },
    {
      vault_name = "vaultname123",
      name       = "keyName123",
    },
    {
      create_limit         = "72h"
      expires_in           = 200
      num_uses             = 10
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}

output "encrypted_protected_certificate" {
  value = provider::az-confidential::encrypt_keyvault_certificate(
    {
      certificate = local.enc_pem_cert,
      password    = "s1cr3t",
    },
    {
      vault_name = "vaultname123",
      name       = "keyName123",
    },
    {
      create_limit         = "72h"
      expires_in           = 200
      num_uses             = 10
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}

output "encrypted_der_certificate" {
  value = provider::az-confidential::encrypt_keyvault_certificate(
    {
      certificate = local.der_cert,
      password    = "s1cr3t",
    },
    {
      vault_name = "vaultname123",
      name       = "keyName123",
    },
    {
      create_limit         = "72h"
      expires_in           = 200
      num_uses             = 10
      provider_constraints = toset(["test", "acceptance"])
    },
    local.public_key
  )
}