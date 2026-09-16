#!/bin/sh
# Regenerates the test fixtures (private keys are deliberately NOT committed).
# Needs: openssl (LibreSSL is fine), ssh-keygen, zip. Run from the repo root:
#   sh tests/fixtures/generate.sh
set -e
[ -n "$PQ_DEBUG" ] && set -x
echo "openssl: $(openssl version)"
cd "$(dirname "$0")"
openssl genrsa -out rsa2048.key 2048 2>/dev/null
openssl req -new -x509 -key rsa2048.key -subj "/CN=rsa-test" -days 30 -out rsa2048.crt 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out ec256.key
openssl req -new -x509 -key ec256.key -subj "/CN=ec-test" -days 30 -sha256 -out ec256.crt 2>/dev/null
# legacy PBES1 and modern PBES2 variants, pinned so LibreSSL and OpenSSL 3 produce the same thing
# single DES lives in the OpenSSL 3 legacy provider; fall back to SHA1+3DES (also PBES1) if unavailable
openssl pkcs8 -topk8 -v1 PBE-MD5-DES -in rsa2048.key -out rsa2048.pk8 -passout pass:x 2>/dev/null \
  || openssl pkcs8 -topk8 -v1 PBE-MD5-DES -provider legacy -provider default -in rsa2048.key -out rsa2048.pk8 -passout pass:x 2>/dev/null \
  || openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -in rsa2048.key -out rsa2048.pk8 -passout pass:x
openssl pkcs8 -topk8 -v2 aes-256-cbc -in rsa2048.key -out rsa2048_pbes2.pk8 -passout pass:x
openssl x509 -in rsa2048.crt -outform DER -out rsa2048.der
echo "secret data" > plain.txt
openssl cms -encrypt -in plain.txt -out enveloped_rsa.p7m -outform DER -aes256 rsa2048.crt
openssl cms -sign -in plain.txt -out signed.p7s -outform DER -signer ec256.crt -inkey ec256.key -nodetach
openssl pkcs12 -export -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -in rsa2048.crt -inkey rsa2048.key -out bundle.p12 -passout pass:x
openssl dhparam -out dh1024.pem 1024 2>/dev/null
openssl enc -aes-256-cbc -pbkdf2 -in plain.txt -out plain.enc -pass pass:x
rm -f id_ed25519 id_ed25519.pub id_rsa id_rsa.pub id_ecdsa id_ecdsa.pub
ssh-keygen -q -t ed25519 -N "" -f id_ed25519
ssh-keygen -q -t rsa -b 3072 -N "pw" -f id_rsa
ssh-keygen -q -t ecdsa -b 256 -N "" -f id_ecdsa
rm -f zipcrypto.zip; zip -q -P secret zipcrypto.zip plain.txt
printf 'age-encryption.org/v1\n-> X25519 abc\nxyz\n-> scrypt salt 18\nxyz\n--- mac\n\000\001' > test.age
printf '%s' 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2ln' > token.jwt
N=$(head -c 256 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
printf '{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"k1"},{"kty":"RSA","n":"%s","e":"AQAB"}]}' "$N" > jwks.json
echo "fixtures generated in $(pwd)"
