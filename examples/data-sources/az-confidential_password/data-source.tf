
data "az-confidential_password" "confidential_password" {
  content = <<-CIPHERTEXT
           H4sIAAAAAAAA/1TSPddzSACA4d6v2N7ZQ4iQYgtkYmSGSXzTJcJDEGRkfPz6Pe/TvXd519e/fzKAZbv/
           mMQNgBv8Hs4im9NZwgortdefWqYYVLhhwjdtoIx77Xr9akd6RNXxmzEqCudI/GB++PSGABk/awFHmniT
           Mi93TuN0k20ndq7Y6zJwf2a90xiDxQZxahwp3DbiBK1q2NZus4oYo4NYmprBTS1xIDpe469ij7rmdYFd
           b5eZPIoeQH9xy2O4WCYLyuXW6825Ss4Ss1teMJiYRcmqcu2eB1IkQuQ3hkQL5Brh3vlIPG6H/Uf2p/La
           nSi+HsoUmeAMvvHjW/payKa0FvT6BbnkMoalr48FIHyRFH3sbr0rjztzqeyPcn/X6oGRrFYCsgN4L+eL
           bty7E6T5/um/sMu4qsUeH7t3T7en6OeNj5QwrxEtQb9PLBzQAGVBqx3UOMN6q2e+uXuSIi5ndA9LWJoS
           NyvzeAYzMpH/aXd5MAU/auRPCwGpdOmUQu5XJu/UbZMC2z79pGD+lOlyHS2VgZ7mkLvcxO39eiO5qaR+
           eg0zZdXKbHJz9bYrabxMZXTkR0sqRfxsFDRtPaK+sD065eG9th3XmgyeUqsGsbjGehli6RIvt5TKjT/4
           +1qv4htucxT5fbBmx+mUzlT4dNa097bgeXBmbk7uCUjGPDFqehnhN69IYVtWnjxzluLIACgdWTG2UgUT
           S13RLopcLTg8AXifpjainLKUCd4RerCLLmEEPsRzMtaPd9hRs7EC7XGBc4axCknzH/eLF7invzH/HwAA
           //+h4R3T5QIAAA==
           CIPHERTEXT
  # The ciphertext above bears the following label(s):
  # - demo
  # - testing
  #
  # Labels are not considered confidential; however, you may want to remove
  # these before checking in this source code into your source control repo.
}

output "decrypted_password" {
  value = data.az-confidential_password.confidential_password.plaintext_password
}