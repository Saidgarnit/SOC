#!/bin/sh
set -e

CERT_ROOT="/certs"
CA_DIR="${CERT_ROOT}/ca"
CERTS_DIR="${CERT_ROOT}/certs"

if [ -f "${CA_DIR}/ca.crt" ]; then
  echo "[certgen] CA already exists, skipping generation."
  exit 0
fi

echo "[certgen] Installing openssl..."
apk add --no-cache openssl >/dev/null

mkdir -p "${CA_DIR}" "${CERTS_DIR}"

echo "[certgen] Generating CA..."
openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
  -subj "/CN=soc-stack-ca" \
  -keyout "${CA_DIR}/ca.key" \
  -out "${CA_DIR}/ca.crt"

for name in elasticsearch kibana fleet-server; do
  cat > /tmp/openssl.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = ${name}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${name}
DNS.2 = localhost
EOF

  echo "[certgen] Generating cert for ${name}..."
  openssl req -new -nodes -newkey rsa:2048 \
    -keyout "${CERTS_DIR}/${name}.key" \
    -out "${CERTS_DIR}/${name}.csr" \
    -config /tmp/openssl.cnf

  openssl x509 -req -in "${CERTS_DIR}/${name}.csr" \
    -CA "${CA_DIR}/ca.crt" \
    -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/${name}.crt" \
    -days 3650 -sha256 \
    -extensions v3_req \
    -extfile /tmp/openssl.cnf
done

chown -R 1000:1000 "${CERT_ROOT}"
chmod -R 640 "${CERT_ROOT}"

echo "[certgen] Certificates generated."
