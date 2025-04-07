#!/bin/bash

# * stop on any error
set -e

# * check if client name provided
if [ -z "$1" ]; then
  echo "Error: Client name is required."
  echo "Usage: $0 client_name [--force]"
  exit 1
fi

# * set environment variables (all uppercase now)
VPN_NAME=${VPN_NAME:-internal.example.com}
VPN_DNS_SRV1=${VPN_DNS_SRV1:-10.2.1.1}
VPN_DNS_SRV2=${VPN_DNS_SRV2:-1.1.1.1}
CERT_DB=${CERT_DB:-sql:/etc/ipsec.d}
CA_NAME=${CA_NAME:-"IKEv2 VPN CA"}
EXPORT_DIR=${EXPORT_DIR:-/etc/ipsec.d/certs/}
CLIENT_NAME="$1"
FORCE_MODE=false

# * export path
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# * check for force mode parameter
if [ "$2" = "--force" ]; then
  FORCE_MODE=true
fi

# * OnDemand domains from environment variable with colon separator
VPN_ONDEMAND_DOMAINS=${VPN_ONDEMAND_DOMAINS:-"connectedtech.dev:*.connectedtech.dev"}
# Convert colon-separated string to array
IFS=':' read -r -a DOMAIN_ARRAY <<< "$VPN_ONDEMAND_DOMAINS"

# * validate client name
if [ "${#CLIENT_NAME}" -gt "64" ] || echo "$CLIENT_NAME" | LC_ALL=C grep -q '[^A-Za-z0-9_-]\+' \
  || case $CLIENT_NAME in -*) true ;; *) false ;; esac; then
  echo "Error: Invalid client name. Use one word only, no special characters except '-' and '_'."
  exit 1
fi

# * check if root
if [ "$(id -u)" != 0 ]; then
  echo "Error: Script must be run as root. Try 'sudo bash $0 $CLIENT_NAME'"
  exit 1
fi

# * check if client certificate already exists
if certutil -L -d "$CERT_DB" -n "$CLIENT_NAME" >/dev/null 2>&1; then
  if [ "$FORCE_MODE" = true ]; then
    echo "## Certificate '$CLIENT_NAME' already exists. Removing due to --force flag..."
    certutil -D -d "$CERT_DB" -n "$CLIENT_NAME" >/dev/null 2>&1
  else
    echo "Error: Client certificate '$CLIENT_NAME' already exists."
    echo "Use '$0 $CLIENT_NAME --force' to override."
    exit 1
  fi
fi

# * check if CA certificate exists
if ! certutil -L -d "$CERT_DB" -n "$CA_NAME" >/dev/null 2>&1; then
  echo "Error: CA certificate '$CA_NAME' not found. Make sure IKEv2 VPN is set up correctly."
  exit 1
fi

# * install required packages if missing
if ! command -v base64 >/dev/null 2>&1 || ! command -v uuidgen >/dev/null 2>&1; then
  echo "## Installing required packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get -yqq update 2>/dev/null
  apt-get -yqq install coreutils uuid-runtime 2>/dev/null
fi

# * generate client certificate (validity 12 months = 1 year)
echo "## Generating client certificate for '$CLIENT_NAME'..."
CLIENT_VALIDITY=12
certutil -z <(head -c 1024 /dev/urandom) \
  -S -c "$CA_NAME" -n "$CLIENT_NAME" \
  -s "O=IKEv2 VPN,CN=$CLIENT_NAME" \
  -k rsa -g 3072 -v "$CLIENT_VALIDITY" \
  -d "$CERT_DB" -t ",," \
  --keyUsage digitalSignature,keyEncipherment \
  --extKeyUsage serverAuth,clientAuth -8 "$CLIENT_NAME" >/dev/null 2>&1 || exit 1

# * generate random password for p12 file
P12_PASSWORD=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' </dev/urandom 2>/dev/null | head -c 18)
if [ -z "$P12_PASSWORD" ]; then
  echo "Error: Could not generate a random password for .p12 file."
  exit 1
fi

# * export p12 file
echo "## Creating client configuration files..."
P12_FILE="$EXPORT_DIR$CLIENT_NAME.p12"
P12_FILE_ENC="$EXPORT_DIR$CLIENT_NAME.enc.p12"
pk12util -W "$P12_PASSWORD" -d "$CERT_DB" -n "$CLIENT_NAME" -o "$P12_FILE_ENC" >/dev/null || exit 1

# * handle OpenSSL 3.x compatibility
if openssl version 2>/dev/null | grep -q "^OpenSSL 3"; then
  CA_CRT="$EXPORT_DIR$CLIENT_NAME.ca.crt"
  CLIENT_CRT="$EXPORT_DIR$CLIENT_NAME.client.crt"
  CLIENT_KEY="$EXPORT_DIR$CLIENT_NAME.client.key"
  PEM_FILE="$EXPORT_DIR$CLIENT_NAME.temp.pem"
  
  openssl pkcs12 -in "$P12_FILE_ENC" -passin "pass:$P12_PASSWORD" -cacerts -nokeys -out "$CA_CRT" || exit 1
  openssl pkcs12 -in "$P12_FILE_ENC" -passin "pass:$P12_PASSWORD" -clcerts -nokeys -out "$CLIENT_CRT" || exit 1
  openssl pkcs12 -in "$P12_FILE_ENC" -passin "pass:$P12_PASSWORD" -passout "pass:$P12_PASSWORD" \
    -nocerts -out "$CLIENT_KEY" || exit 1
  
  cat "$CLIENT_KEY" "$CLIENT_CRT" "$CA_CRT" > "$PEM_FILE"
  /bin/rm -f "$CLIENT_KEY" "$CLIENT_CRT" "$CA_CRT"
  
  openssl pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -export -in "$PEM_FILE" -out "$P12_FILE_ENC" \
    -legacy -name "$CLIENT_NAME" -passin "pass:$P12_PASSWORD" -passout "pass:$P12_PASSWORD" || exit 1
  
  openssl pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -export -in "$PEM_FILE" -out "$P12_FILE" \
    -legacy -name "$CLIENT_NAME" -passin "pass:$P12_PASSWORD" -passout pass: || exit 1
  
  /bin/rm -f "$PEM_FILE"
else
  # * for older OpenSSL versions
  pk12util -W "" -d "$CERT_DB" -n "$CLIENT_NAME" -o "$P12_FILE" >/dev/null || exit 1
fi

chmod 600 "$P12_FILE"

# * create mobileconfig (Apple iOS/macOS)
CA_BASE64=$(certutil -L -d "$CERT_DB" -n "$CA_NAME" -a | grep -v CERTIFICATE)
[ -z "$CA_BASE64" ] && { echo "Error: Could not encode $CA_NAME certificate."; exit 1; }
P12_BASE64=$(base64 -w 52 "$P12_FILE_ENC")
[ -z "$P12_BASE64" ] && { echo "Error: Could not encode .p12 file."; exit 1; }
UUID1=$(uuidgen)
[ -z "$UUID1" ] && { echo "Error: Could not generate UUID value."; exit 1; }
MC_FILE="$EXPORT_DIR$CLIENT_NAME.mobileconfig"

DOMAIN_ENTRIES=""
for domain in "${DOMAIN_ARRAY[@]}"; do
  DOMAIN_ENTRIES="$DOMAIN_ENTRIES
                            <string>$domain</string>"
done

cat > "$MC_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>Certificate</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>19</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>LifeTimeInMinutes</key>
          <integer>1410</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableRedirect</key>
        <true/>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <integer>0</integer>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>19</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>LifeTimeInMinutes</key>
          <integer>1410</integer>
        </dict>
        <key>LocalIdentifier</key>
        <string>$CLIENT_NAME</string>
        <key>PayloadCertificateUUID</key>
        <string>$UUID1</string>
        <key>OnDemandEnabled</key>
        <integer>1</integer>
        <key>OnDemandRules</key>
        <array>
            <dict>
                <key>Action</key>
                <string>EvaluateConnection</string>
                <key>ActionParameters</key>
                <array>
                    <dict>
                        <key>DomainAction</key>
                        <string>ConnectIfNeeded</string>
                        <key>Domains</key>
                        <array>$DOMAIN_ENTRIES
                        </array>
                    </dict>
                </array>
            </dict>
          <dict>
            <key>Action</key>
            <string>Ignore</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>$VPN_NAME</string>
        <key>RemoteIdentifier</key>
        <string>$VPN_NAME</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
        <key>IncludeAllNetworks</key>
        <false/>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>0</integer>
        <key>IncludeAllNetworks</key>
        <false/>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadOrganization</key>
      <string>IKEv2 VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>$VPN_NAME</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
    <dict>
      <key>Password</key>
      <string>$P12_PASSWORD</string>
      <key>PayloadCertificateFileName</key>
      <string>$CLIENT_NAME</string>
      <key>PayloadContent</key>
      <data>
$P12_BASE64
      </data>
      <key>PayloadDescription</key>
      <string>Adds a PKCS#12-formatted certificate</string>
      <key>PayloadDisplayName</key>
      <string>$CLIENT_NAME</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.security.pkcs12.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadUUID</key>
      <string>$UUID1</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
    <dict>
      <key>PayloadContent</key>
      <data>
$CA_BASE64
      </data>
      <key>PayloadCertificateFileName</key>
      <string>ikev2vpnca</string>
      <key>PayloadDescription</key>
      <string>Adds a CA root certificate</string>
      <key>PayloadDisplayName</key>
      <string>Certificate Authority (CA)</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.security.root.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN $VPN_NAME</string>
  <key>PayloadIdentifier</key>
  <string>com.apple.vpn.managed.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

chmod 600 "$MC_FILE"

# * create Android profile (strongSwan)
P12_BASE64_ONELINE=$(base64 -w 52 "$P12_FILE" | sed 's/$/\\n/' | tr -d '\n')
[ -z "$P12_BASE64_ONELINE" ] && { echo "Error: Could not encode .p12 file."; exit 1; }
UUID2=$(uuidgen)
[ -z "$UUID2" ] && { echo "Error: Could not generate UUID value."; exit 1; }
SSWAN_FILE="$EXPORT_DIR$CLIENT_NAME.sswan"

cat > "$SSWAN_FILE" <<EOF
{
  "uuid": "$UUID2",
  "name": "IKEv2 VPN $VPN_NAME",
  "type": "ikev2-cert",
  "remote": {
    "addr": "$VPN_NAME"
  },
  "local": {
    "p12": "$P12_BASE64_ONELINE",
    "rsa-pss": "true"
  },
  "ike-proposal": "aes256-sha256-modp2048",
  "esp-proposal": "aes128gcm16",
  "include_subnets": ["10.2.1.0/24"]
}
EOF

chmod 600 "$SSWAN_FILE"

# * remove temporary file
/bin/rm -f "$P12_FILE_ENC"

# * show client information
echo
echo "================================================"
echo
echo "IKEv2 client '$CLIENT_NAME' added!"
echo
echo "Server: $VPN_NAME"
echo
echo "Client configuration files generated:"
echo "$P12_FILE (for Windows & Linux)"
echo "$SSWAN_FILE (for Android)"
echo "$MC_FILE (for iOS & macOS)"
echo
echo "Password for client config file (if needed): $P12_PASSWORD"
echo
echo "================================================"
echo
echo "Instructions for configuring clients: https://vpnsetup.net/clients"
echo

exit 0