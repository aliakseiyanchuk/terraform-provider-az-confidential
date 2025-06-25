TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=github.com
NAMESPACE=aliakseiyanchuk
NAME=az-confidential
BINARY=terraform-provider-${NAME}
TF_GEN_BINARY=tfgen-${NAME}
VERSION=0.9
BUILD_PRERELEASE=alpha.0
OS_ARCH=darwin_arm64

LOCAL_MIRROR_PATH?=~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

GOPROXY?=https://nexus/repository/go-all/
GOPATH?=/Users/aliakseiyanchuk/go
GOROOT?=/usr/local/go
GO111MODULE=on

install:
	go install -v ./...

# Generate ephemeral (=safe to throw away and re-generate) keys for unit testing
ephemeral_keys:
	cd core && \
		mkdir testkeymaterial && \
		cd test-key-material && \
		mkdir km && cd km && \
		openssl genrsa -out ephemeral-rsa-private-key.pem 4096 && \
		openssl rsa -in ephemeral-rsa-private-key.pem -outform der -out ephemeral-rsa-private-key.der && \
		openssl rsa -in ephemeral-rsa-private-key.pem -pubout -out ephemeral-rsa-public-key.pem && \
		openssl genrsa -out ephemeral-rsa-private-key-encrypted.pem -aes256 -passout pass:s1cr3t 4096 && \
		openssl rsa -in ephemeral-rsa-private-key-encrypted.pem -passin pass:s1cr3t -outform der -out  ephemeral-rsa-private-key-encrypted.der -aes256 -passout pass:s1cr3t && \
		openssl rsa -in ephemeral-rsa-private-key-encrypted.pem -passin:s1cr3t -pubout -out ephemeral-rsa-public-key-encrypted.pem && \
		openssl ecparam -name secp521r1 -genkey -noout -out private-ec-key-secp521r1.pem && \
		openssl ecparam -name secp384r1 -genkey -noout -out private-ec-key-secp384r1.pem && \
		openssl ecparam -name prime256v1 -genkey -noout -out private-ec-key-prime256v1.pem && \
		openssl ecparam -name secp256k1 -genkey -noout -out private-ec-key-secp256k1.pem && \
		openssl req -subj='/DC=github.com/DC=aliakseiyanchuk/DC=az-confidential/CN=demo-app' -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout cert-key.pem -out cert-pub.pem && \
		cat cert-key.pem cert-pub.pem > ephemeral-certificate.pem && \
		openssl pkcs12 -export -out cert.pkcs12 -inkey cert-key.pem -in cert-pub.pem -password pass:s1cr3t && \
		openssl pkcs12 -in cert.pkcs12 -passin pass:s1cr3t -out cert.pkcs12.pem -nodes && \
		openssl req -subj='/DC=github.com/DC=aliakseiyanchuk/DC=az-confidential/CN=demo-app' -newkey rsa:2048 -new -passout pass:s1cr3t -x509 -days 3650 -keyout cert-key_encrypted.pem -out cert-pub_certyped.pem && \
		cat cert-key_encrypted.pem cert-pub_certyped.pem > ephemeral-certificate-encrypted.pem && \



generate:
	cd tools; go generate ./...

test:
	go test ${TEST}

acceptance_test: install
	TF_ACC=1 go test ./acceptance

tfgen:
	go build -o ${TF_GEN_BINARY} ./bin/tfgen
	chmod u+x ${TF_GEN_BINARY}
