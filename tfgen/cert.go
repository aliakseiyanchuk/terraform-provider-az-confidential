package main

import (
	_ "embed"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
)

const certCliArg = "cert"

//go:embed cert_template.tmpl
var certTFTemplate string

var certCmd = flag.NewFlagSet(certCliArg, flag.ContinueOnError)

type CertTFGetParams struct {
	SecretTFGenParams

	requirePassword bool
}

var certParams = CertTFGetParams{}

func init() {
	certCmd.StringVar(&certParams.secretFromFile,
		"cert-file",
		"",
		"Read secret from specified file")

	certCmd.BoolVar(&certParams.secretInputIsBase64,
		"base64",
		false,
		"Input is base-64 encoded")

	certCmd.BoolVar(&certParams.requirePassword,
		"encrypted-private-key",
		false,
		"Specify that private key is encrypted")
}

func generateConfidentialCertificateTerraformTemplate(kwp KeyWrappingParams, args []string) (string, error) {
	if vErr := kwp.ValidateHasDestination(); vErr != nil {
		return "", vErr
	}

	if parseErr := certCmd.Parse(args); parseErr != nil {
		return "", parseErr
	}

	certData, readErr := ReadInput("Enter certificate data (hit Enter twice to end input)",
		certParams.secretFromFile,
		certParams.secretInputIsBase64,
		true)

	if readErr != nil {
		return "", readErr
	}

	objType := "certificate"
	certPass := ""

	if certParams.requirePassword {
		readCertPass, certPassErr := ReadInput("Enter certificate password", "", false, false)
		if certPassErr != nil {
			return "", errors.New(fmt.Sprintf("Could not read certificate password: %s", certPassErr.Error()))
		}

		certPass = string(readCertPass)
	}

	payloadBytes := core.WrapDualPayload(certData, &certPass, objType, kwp.GetLabels())
	fmt.Println(base64.StdEncoding.EncodeToString(payloadBytes))

	em, emErr := core.CreateEncryptedMessage(kwp.loadedRsaPublicKey, payloadBytes)
	if emErr != nil {
		return "", emErr
	}

	rv := BaseTFTemplateParms{
		EncryptedContent:     em.GetSecretExpr(),
		ContentEncryptionKey: em.GetContentEncryptionKeyExpr(),

		WrappingKeyCoordinate: kwp.WrappingKeyCoordinate,
		DestinationCoordinate: kwp.DestinationCoordinate,
	}

	return rv.Render("cert", certTFTemplate)
}
