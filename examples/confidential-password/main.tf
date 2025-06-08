terraform {
  required_providers {
    az-confidential = {
      source = "hashicorp.com/lspwd2/az-confidential"
    }
  }
}

provider "az-confidential" {
  tenant_id = var.az_tenant_id
  subscription_id = var.az_subscription_id
  client_id = var.az_client_id
  client_secret = var.az_client_secret

  oaep_label = "dev_examples"

  default_wrapping_key = {
    vault_name = var.az_default_vault_name
    name = var.az_default_wrapping_key
    version = var.az_default_wrapping_key_version
  }
}

data "az-confidential_password" "example_pwd" {
  encrypted_password = "w9tD1grI9gC2Dhkhrpxrdm65V5PbckQaCEbwBs8oK9hgSQZj1JF4lf0Vnwf+mkOxiFH5XOPgN+tnDt+W4Vu5AdMdvgH0h0TDnHAMx/CsnAbcXDnEaXhQvbBoWz79sllLiuDVdkSeCRPMPuJ0aONuhe1ZryTGKTsx18zaPtXhX3Ivda3T2qRu6haDI8YPP8leq8ZW7rXhEA94J/bBZlspkAjiBRfAdqoBlf9Wi6HM7rjT+8SREjN45a5nptyaWnn35riHI0tXwkuuM8D9/+xHlqINiE8i7NQddPqIoD2FFrYa5z1TgzR4MHz8NimKtWa/lch7Q/gq+qn2NILByCIEBX+/UPvwKT7noetXw2C8G2+vjnVr1oQ6jnYckLjaK3jPMUOCeJzXFu5dosxNyL3M7pnUMRsXjdOOtpa/rZBgp1K6cFxJRvq6U91PmSmddsrOLUVsKozpBRkx00c5eqDzXGt75kFsWhnzq+CcYQXhVmWNczkxpGnu+6U5tfV202JiC+80Ihh19YoYTllzO+O9XJhFLUFor5NAxAhE8Ilq4+jhzZFKPXZT4p3BRR80Ycj0Ds+q6hJinA6LBiiQRaB+i+96sBjKHQ660/gLLDxZwEicvqVqtCOL+vjLRYB8L+9RoC9X8rFeR4obhdUNLXugxURbp+7thCqPAl1dKhWCBww="
}

output "decrypted_password" {
  value = data.az-confidential_password.example_pwd.plaintext_password
}