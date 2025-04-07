# ipsec

**IKEv2/IPsec VPN server with programmable API**

IKEv2/IPsec server setup scripts for Debain-based distribution. Implemented including script to create additional user with RSA certificate authentication.

## Usage

#### Setup

```bash
export VPN_NAME="internal.example.com"
export VPN_IPSEC_PSK="$(openssl rand -base64 24)"
export VPN_DNS_SRV1="8.8.8.8"
export VPN_DNS_SRV2="8.8.4.4"
export VPN_POOL="10.2.231.0/24"
export VPN_INTERNAL_SUBNET="10.2.230.0/24"
export CERT_DB="sql:/etc/ipsec.d"
export CA_NAME="Example VPN"

curl -fsSL https://raw.githubusercontent.com/connectedtechco/ipsec/refs/heads/main/script/setup.sh | bash -
```

## Credit

- **[bsthun](https://github.com/BSthun)** Author and developer
- **[hwdsl2](https://github.com/hwdsl2/setup-ipsec-vpn)** Original VPN setup script
