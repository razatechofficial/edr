#!/usr/bin/env bash
# Generate a private CA, control-plane server cert, and agent client cert for pilot mTLS.
set -euo pipefail

OUT="${1:-/etc/edr-controlplane/tls}"
DAYS="${TLS_DAYS:-825}"
CN="${TLS_CN:-edr-controlplane}"
SAN="${TLS_SAN:-DNS:localhost,DNS:edr-controlplane,IP:127.0.0.1}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

install -d -m 0750 "${OUT}"
cd "${OUT}"

if [[ -f ca.crt && -f server.crt && -f agent-client.crt ]]; then
	echo "TLS material already exists in ${OUT}; skip generation."
	exit 0
fi

echo "==> generating CA"
openssl genrsa -out ca.key 4096
chmod 0600 ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days "${DAYS}" \
	-subj "/CN=EDR Control Plane CA" -out ca.crt

echo "==> generating server key + CSR"
openssl genrsa -out server.key 2048
chmod 0600 server.key
openssl req -new -key server.key -subj "/CN=${CN}" -out server.csr

cat > server.ext <<EOF
subjectAltName=${SAN}
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
	-out server.crt -days "${DAYS}" -sha256 -extfile server.ext

echo "==> generating agent client key + cert"
openssl genrsa -out agent-client.key 2048
chmod 0600 agent-client.key
openssl req -new -key agent-client.key -subj "/CN=edr-agent" -out agent-client.csr
cat > agent.ext <<EOF
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in agent-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
	-out agent-client.crt -days "${DAYS}" -sha256 -extfile agent.ext

chmod 0644 ca.crt server.crt agent-client.crt
rm -f server.csr agent-client.csr server.ext agent.ext ca.srl

echo "TLS material written to ${OUT}"
echo "  CA:            ${OUT}/ca.crt"
echo "  Server:        ${OUT}/server.crt ${OUT}/server.key"
echo "  Agent client:  ${OUT}/agent-client.crt ${OUT}/agent-client.key"
