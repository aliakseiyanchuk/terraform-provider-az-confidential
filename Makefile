TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=github.com
NAMESPACE=aliakseiyanchuk
NAME=az-confidential
BINARY=terraform-provider-${NAME}
TF_GEN_BINARY=tfgen-${NAME}
VERSION=0.1
BUILD_PRERELEASE=alpha.0
OS_ARCH=darwin_arm64

LOCAL_MIRROR_PATH?=~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

GOPROXY?=https://nexus/repository/go-all/
GOPATH?=/Users/aliakseiyanchuk/go
GOROOT?=/usr/local/go
GO111MODULE=on


build:
	GOPROXY=${GOPROXY} GOPATH=${GOPATH} GOROOT=${GOROOT} GO111MODULE=${GO111MODULE}
	go build -o ${BINARY}

install: build
	mkdir -p ${LOCAL_MIRROR_PATH}
	mv ${BINARY} ${LOCAL_MIRROR_PATH}


# Supported curve: secp521r1, secp384r1, prime256v1, secp256k1
generate_ephemeral_keys:
	cd core && \
		openssl genrsa -out ephemeral-rsa-private-key.pem 4096 && \
		openssl rsa -in ephemeral-rsa-private-key.pem -pubout -out ephemeral-rsa-public-key.pem && \
		openssl ecparam -name secp521r1 -genkey -noout -out private-ec-key-secp521r1.pem && \
		openssl ecparam -name secp384r1 -genkey -noout -out private-ec-key-secp384r1.pem && \
		openssl ecparam -name prime256v1 -genkey -noout -out private-ec-key-prime256v1.pem && \
		openssl ecparam -name secp256k1 -genkey -noout -out private-ec-key-secp256k1.pem

generate:
	cd tools; go generate ./...

build_tf_generator:
	go build -o ${TF_GEN_BINARY} ./tfgen
	chmod u+x ${TF_GEN_BINARY}
