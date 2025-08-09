
data "az-confidential_general_content" "confidential_content" {
  content = <<-CIPHERTEXT
           H4sIAAAAAAAA/1TTu9KyugKA4Z6rsHfviYAgfDOrEARPgBA52iHki+EQIAQFr37N+rv/Ld/++f9/Gdbx
           7K3MmxdaXvjnCCZDOUcOaQn/WW0Ea+4JW35W4k5RNrIibjTB7UrUQPSLGKIF+lkVHUNg5IxQDN6i4Dd5
           gVpEudnRkbOcUD7+rASfdW9SIvbXLVHb/Y+jkROKhXDp0c8KI4pY3oCioxxRLgh1kljbtCeFOx+nCXba
           FhRN6H57uu6QwvxqkJz6yda1fVV2qBuxpyOuDmE843FyNVmYCoeXTaSLuFZBH29TELDRxWbh59JOnbfb
           pwypr+RPaDqBnJ49jWGF2mg05OBmYCyUm7dEd1k9nmMZhaBTr1DT4BXPOL6Gkqy+Qb2rwpchjwB6WgQi
           Fu9xe4GZD8Qoch9CF/dS/vW72TVONzXlSfnC6SYd51xZ6KlSo5v+DPYDTDUm72R9OpZGMj/Uwd3pR2Ak
           kvCVPp987816fXD33Ae7dkqSRCMDnEr97qnoiFNkhsPN6e8iHJgGans/1QnArXRVnELYxoVqVPPSSuao
           G9zpiOtK3zpyI56ui9bOic2eYaGfsnd4EdXKrgnsLxmW0JI1GkiEpnxb4pSHYjWvkz1vl644rMHAxeq2
           3OTKXryvZTipFLw0c6iJePgu3K7Gxuwe7ja/vwSD+s/gpMua+tnkw1zdRni9L/qsveHRCOYpWWdjkckH
           PMnnHWh1eCn85L190bz6dsvZEU6uTQ57ff+JkrhqqJyRJMlMMUBy3J6oNaMLJMHlc1OOYfiKqWgahSZl
           GzHo7mHM7lh4kvXj2U7SrwSt4SDpcgRn1wT3db/hysPG2DOatA3g0Tky55FqT0M/szj4ZeWvQ4hTCDVU
           v7YanatTnw+kItNnSIzadNTNyy2AEl2tuxHTYG9N4z/CH02Wd/hb178BAAD//zThoj92AwAA
           CIPHERTEXT
  # The ciphertext above bears the following label(s):
  # - demo
  # - testing
  #
  # Labels are not considered confidential; however, you may want to remove
  # these before checking in this source code into your source control repo.
}

output "decrypted_content" {
  value = data.az-confidential_general_content.confidential_content.plaintext
}