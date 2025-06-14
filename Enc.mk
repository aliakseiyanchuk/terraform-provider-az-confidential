PUBLIC_KEY_FILE ?= "wrapping_key_pk.pem"
PASSWORD ?= "a very confidential password"


TFGEN_EXEC=./tfgen-az-confidential

OUTPUT_VAULT_NAME?="demo-vault"
OUTPUT_VAULT_SECRET="example-certificate"
PUBKEY?=wrapping_key_pk.pem

OAEP_LABEL?=$(shell LC_CTYPE=C tr -dc 'A-Za-z0-9' </dev/random | head -c 13)
OAEP_LABEL_HEX=$(shell printf ${OAEP_LABEL} | xxd -ps)
OAEP_LABEL_B64=$(shell printf ${OAEP_LABEL} | base64 -w 0)
OAEP_ENFORCEMENT?=-fixed-oaep-label ${OAEP_LABEL_B64}

encrypt_password_openssl:
	printf "${PASSWORD}" \
	  | openssl pkeyutl -encrypt \
			-inkey ${PUBLIC_KEY_FILE} -pubin \
			-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_oaep_label:${OAEP_LABEL_HEX} \
	  | base64 -w 0
	@printf "HEX OAEP LABEL=%s\n" ${OAEP_LABEL_HEX}
	@printf "B64 OAEP LABEL=%s\n" ${OAEP_LABEL_B64}

encrypt_password_openssl_no_label:
	printf "${PASSWORD}" \
	  | openssl pkeyutl -encrypt \
			-inkey ${PUBLIC_KEY_FILE} -pubin \
			-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
	  | base64 -w 0

# Encrypt text secret read from the command-line
encrypt_secret:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
	${OAEP_ENFORCEMENT} \
	secret

# Encrypt text secret read from the command-line
encrypt_password:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${OAEP_ENFORCEMENT} \
	password

encrypt_key:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${OAEP_ENFORCEMENT} \
	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
	key

encrypt_cert:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${OAEP_ENFORCEMENT} \
	-output-vault ${OUTPUT_VAULT_NAME} -output-vault-secret ${OUTPUT_VAULT_SECRET} \
	certificate
