# Makefile for testing TF Generation routines
TFGEN_EXEC=./tfgen-az-confidential

OUTPUT_VAULT_NAME?="demo-vault"
OUTPUT_VAULT_SECRET="example-secret"
OUTPUT_VAULT_KEY="example-key"
OUTPUT_VAULT_CERTIFICATE="example-certificate"

OAEP_ENFORCEMENT?=-fixed-oaep-label testing

PUBKEY?=wrapping_key_pk.pem

RSA_KEY=./core/ephemeral-rsa-private-key.pem
EC_KEY=./core/private-ec-key-prime256v1.pem
RSA_KEY_DER_FORM=./core/ephemeral-rsa-private-key.der
ENC_RSA_KEY=./core/ephemeral-rsa-private-key-encrypted.pem
ENC_RSA_KEY_DER_FORM=./core/ephemeral-rsa-private-key-encrypted.der

PWD_FILE=./ephemeral-password.txt

test_rsa_key_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${RSA_KEY}

test_ec_key_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${EC_KEY} ; test "$?" -eq 2

test_rsa_key_gen_der:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${RSA_KEY_DER_FORM}

test_enc_rsa_key_gen:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${ENC_RSA_KEY} -password-file=${PWD_FILE}

test_enc_rsa_key_manual_pwd:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${ENC_RSA_KEY}

test_enc_rsa_key_gen_der:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
    	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
    	${OAEP_ENFORCEMENT} \
    	key \
    	-key-file ${ENC_RSA_KEY_DER_FORM} -password-file=${PWD_FILE}

test_enc_rsa_key_manual_pwd_der:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
		-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
		${OAEP_ENFORCEMENT} \
		key \
		-key-file ${ENC_RSA_KEY_DER_FORM}