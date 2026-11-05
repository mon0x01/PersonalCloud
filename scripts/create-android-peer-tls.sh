#!/usr/bin/env bash
set -euo pipefail

umask 077
OUT="${1:-$HOME/.local/share/personalcloud-android-peer-tls}"
mkdir -p "$OUT"
chmod 700 "$OUT"
for existing in phone-ca.key phone-ca.crt phone-server.key phone-server.crt phone-server.p12 desktop-truststore.p12; do
  if [[ -e "$OUT/$existing" ]]; then
    echo "Refusing to overwrite existing TLS material: $OUT/$existing" >&2
    echo "Choose a new output directory as the script argument, or back up and remove the old set deliberately." >&2
    exit 1
  fi
done

read -rp "Android phone's reachable IPv4 address: " PHONE_IP
if ! awk -F. 'NF == 4 { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1; exit 0 } { exit 1 }' <<< "$PHONE_IP"; then
  echo "Invalid IPv4 address." >&2
  exit 1
fi

read -rsp "Choose a password for the Android PKCS#12 identity: " P12_PASS
echo
read -rsp "Choose a password for the desktop truststore: " TRUST_PASS
echo
if [[ ${#P12_PASS} -lt 8 || ${#TRUST_PASS} -lt 8 ]]; then
  echo "Use passwords of at least 8 characters." >&2
  exit 1
fi

rm -f "$OUT/phone-ca.key" "$OUT/phone-ca.crt" "$OUT/phone-server.key" \
  "$OUT/phone-server.csr" "$OUT/phone-server.crt" "$OUT/phone-server.p12" \
  "$OUT/desktop-truststore.p12" "$OUT/phone-server.ext" "$OUT/phone-ca.srl"

openssl genrsa -out "$OUT/phone-ca.key" 3072
openssl req -x509 -new -key "$OUT/phone-ca.key" -sha256 -days 1825 \
  -out "$OUT/phone-ca.crt" -subj "/CN=PersonalCloud Android Peer CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
openssl genrsa -out "$OUT/phone-server.key" 3072
openssl req -new -key "$OUT/phone-server.key" -out "$OUT/phone-server.csr" \
  -subj "/CN=PersonalCloud-Android"
cat > "$OUT/phone-server.ext" <<EXT
subjectAltName=IP:${PHONE_IP}
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid,issuer
EXT
openssl x509 -req -in "$OUT/phone-server.csr" -CA "$OUT/phone-ca.crt" \
  -CAkey "$OUT/phone-ca.key" -CAcreateserial -out "$OUT/phone-server.crt" \
  -days 397 -sha256 -extfile "$OUT/phone-server.ext"
openssl pkcs12 -export -name personalcloud-android -inkey "$OUT/phone-server.key" \
  -in "$OUT/phone-server.crt" -certfile "$OUT/phone-ca.crt" \
  -out "$OUT/phone-server.p12" -passout "pass:${P12_PASS}"
keytool -importcert -noprompt -alias personalcloud-android-ca -file "$OUT/phone-ca.crt" \
  -keystore "$OUT/desktop-truststore.p12" -storetype PKCS12 -storepass "$TRUST_PASS" >/dev/null
openssl verify -CAfile "$OUT/phone-ca.crt" "$OUT/phone-server.crt"
chmod 600 "$OUT/phone-ca.key" "$OUT/phone-server.key" "$OUT/phone-server.p12" "$OUT/desktop-truststore.p12"
chmod 644 "$OUT/phone-ca.crt" "$OUT/phone-server.crt"
unset P12_PASS TRUST_PASS

cat <<INFO

Created Android peer TLS materials in: $OUT

Transfer to Android:
  phone-server.p12  (private server identity)
  desktop-server.crt (public laptop certificate, generated separately)

Desktop peer truststore:
  $OUT/desktop-truststore.p12

Start PersonalCloud with:
  PERSONALCLOUD_TLS_TRUSTSTORE="$OUT/desktop-truststore.p12" \\
  PERSONALCLOUD_TLS_TRUSTSTORE_PASSWORD='<desktop truststore password>' \\
  ./run.sh

The Android certificate is valid only for: $PHONE_IP
Regenerate it if that address changes. Never transfer phone-ca.key.
INFO
