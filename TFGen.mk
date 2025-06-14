# Makefile for testing TF Generation routines
TFGEN_EXEC=./tfgen-az-confidential

OUTPUT_VAULT_NAME?="demo-vault"
OUTPUT_VAULT_SECRET="example-secret"
OUTPUT_VAULT_CERT="example-cert"
OUTPUT_VAULT_KEY="example-key"
OUTPUT_VAULT_CERTIFICATE="example-certificate"

OAEP_ENFORCEMENT?=-fixed-oaep-label testing

PUBKEY?=wrapping_key_pk.pem

SECRET_FILE=./example-secret-file.txt

RSA_KEY=./core/ephemeral-rsa-private-key.pem
EC_KEY=./core/private-ec-key-prime256v1.pem
RSA_KEY_DER_FORM=./core/ephemeral-rsa-private-key.der
ENC_RSA_KEY=./core/ephemeral-rsa-private-key-encrypted.pem
ENC_RSA_KEY_DER_FORM=./core/ephemeral-rsa-private-key-encrypted.der

CERT_PEM_FILE=./core/ephemeral-certificate.pem
CERT_ENC_FILE=./core/ephemeral-certificate-encrypted.pem
CERT_PKCS12_CONVERTED=./core/cert.pkcs12.pem

PWD_FILE=./ephemeral-password.txt

# Generate the wrapping key for testing TF generator
generate_wrapping_public_key:
	openssl genrsa -out ./wrapping_key.pem 4096 && \
	openssl genrsa -in ./wrapping_key.pem  -pubout -out wrapping_key_pk.pem 4096 && \

test_secret_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	secret \
    	-secret-file ${SECRET_FILE}

test_rsa_key_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${RSA_KEY}

test_ec_key_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${EC_KEY} ; test "$?" -eq 2

test_rsa_key_gen_der:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${RSA_KEY_DER_FORM}

test_enc_rsa_key_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${ENC_RSA_KEY} -password-file=${PWD_FILE}

test_enc_rsa_key_manual_pwd:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${ENC_RSA_KEY}

test_enc_rsa_key_gen_der:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${ENC_RSA_KEY_DER_FORM} -password-file=${PWD_FILE}

test_enc_rsa_key_manual_pwd_der:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
		-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_SECRET} \
		${OAEP_ENFORCEMENT} \
		key \
		-key-file ${ENC_RSA_KEY_DER_FORM}

test_cert_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
		-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_CERT} \
		${OAEP_ENFORCEMENT} \
		certificate \
		-cert-file ${CERT_PEM_FILE}

test_cert_enc_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
		-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_CERT} \
		${OAEP_ENFORCEMENT} \
		certificate \
		-cert-file ${CERT_PEM_FILE} -cert-password ${PWD_FILE}

test_cert_enc_manual_pwd:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
		-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_CERT} \
		${OAEP_ENFORCEMENT} \
		certificate \
		-cert-file ${CERT_ENC_FILE}

test_cert_pkcs12_conv_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
		-output-vault ${OUTPUT_VAULT_NAME} -output-vault-object ${OUTPUT_VAULT_CERT} \
		${OAEP_ENFORCEMENT} \
		certificate \
		-cert-file ${CERT_PKCS12_CONVERTED}