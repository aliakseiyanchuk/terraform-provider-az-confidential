PUBLIC_KEY_FILE ?= "wrapping_key_pk.pem"
PASSWORD ?= "a very confidential password"


TFGEN_EXEC=./tfgen-az-confidential

OUTPUT_VAULT_NAME?="demo-vault"
OUTPUT_VAULT_OBJECT="demo"
PUBKEY?=wrapping_key_pk.pem

LABELS?=-provider-constraints demo,testing
OPTIONS?=
CMD_OPTIONS?=

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
	${LABELS} ${OPTIONS} \
	kv secret \
	-destination-vault ${OUTPUT_VAULT_NAME} -destination-secret-name ${OUTPUT_VAULT_OBJECT} \

# Encrypt text secret read from the command-line
encrypt_password:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${LABELS} ${OPTIONS} \
	general password

encrypt_key:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${LABELS} ${OPTIONS}\
	kv key \
	-destination-vault ${OUTPUT_VAULT_NAME} -destination-key-name ${OUTPUT_VAULT_OBJECT} \

encrypt_cert:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${LABELS} ${OPTIONS} \
	kv certificate \
	-destination-vault ${OUTPUT_VAULT_NAME} -destination-cert-name ${OUTPUT_VAULT_OBJECT} \

encrypt_apim_named_value:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${LABELS} ${OPTIONS} \
	apim named_value ${CMD_OPTIONS}

encrypt_apim_subscription:
	${TFGEN_EXEC} -pubkey ${PUBKEY} \
	${LABELS} ${OPTIONS} \
	apim subscription ${CMD_OPTIONS}