// Copyright (c) HashiCorp, Inc.

package testkeymaterial

import _ "embed"

//go:embed km/ephemeral-rsa-public-key.pem
var EphemeralRsaPublicKey []byte

//go:embed km/ephemeral-rsa-private-key.pem
var EphemeralRsaKeyText []byte

//go:embed km/ephemeral-rsa-private-key.der
var EphemeralRsaKeyDERForm []byte

//go:embed km/ephemeral-rsa-private-key-encrypted.pem
var EphemeralEncryptedRsaKeyText []byte

//go:embed km/ephemeral-rsa-private-key-encrypted.der
var EphemeralEncryptedRsaKeyDERForm []byte

// Secp256r1EcPrivateKey This is "P-521" curve
//
//go:embed km/private-ec-key-secp521r1.pem
var Secp256r1EcPrivateKey []byte

// Secp384r1EcPrivateKey THis is "P-384" curve
//
//go:embed km/private-ec-key-secp384r1.pem
var Secp384r1EcPrivateKey []byte

// Prime256v1EcPrivateKey his is "P-256"
//
//go:embed km/private-ec-key-prime256v1.pem
var Prime256v1EcPrivateKey []byte

// Prime256v1EcPrivateKey This is "P-256K" curve; however, it isn't supported.
// DISABLED go:embed private-ec-key-secp256k1.pem
//var Prime256v1EcPrivateKey string

//go:embed km/ephemeral-rsa-private-key.pem
var RsaPrivateKey []byte

//go:embed km/ephemeral-certificate.pem
var EphemeralCertificatePEM []byte

//go:embed km/cert.pkcs12
var EphemeralCertPFX12 []byte

//go:embed km/cert.pkcs12
var Pkcs12File []byte

//func TestPKCS12Import(t *testing.T) {
//	_, _, pwdErr := pkcs12.Decode(Pkcs12File, "s1cr3t")
//	assert.Nil(t, pwdErr)
//}
