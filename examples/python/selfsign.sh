#!/bin/bash
set -x
mkdir ./output
pushd ./output
DOMAIN=localhost.$WEBSITE
ANY_INTEGER=$RANDOM
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048 || openssl genrsa 2048
openssl req -new -key key.pem -days 1096 -extensions v3_ca -batch -out example.csr -utf8 -subj "/CN=$DOMAIN"

cat <<EOF > openssl.ss.cnf
    basicConstraints = CA:FALSE
    subjectAltName =DNS:$DOMAIN
    extendedKeyUsage =serverAuth
EOF

openssl x509 -req -sha256 -days 3650 -in example.csr -signkey key.pem -set_serial $ANY_INTEGER -extfile openssl.ss.cnf -out localhost.pem

popd
