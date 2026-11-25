#!/bin/sh
set -eu
cd /certs
CA=e2e-test-only-ca
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$CA.key" -out "$CA.pem" -days 3 -subj "/CN=jaunt e2e test-only CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
for name in "$@"; do
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$name.key" -out "$name.csr" -subj "/CN=$name.e2e.test" 2>/dev/null
  printf 'subjectAltName=DNS:%s.e2e.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$name" >"$name.ext"
  openssl x509 -req -in "$name.csr" -CA "$CA.pem" -CAkey "$CA.key" -CAcreateserial \
    -out "$name.crt" -days 3 -extfile "$name.ext" 2>/dev/null
  cat "$name.crt" "$CA.pem" >"$name.pem"
  rm -f "$name.csr" "$name.ext" "$name.crt"
done
rm -f "$CA.srl" "$CA.key"
chmod 0644 ./*.pem
chmod 0600 ./*.key
