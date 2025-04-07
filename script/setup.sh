#!/bin/bash

# * set environment variables
VPN_NAME=${VPN_NAME:-internal.example.com}
VPN_IPSEC_PSK=${VPN_IPSEC_PSK:-0032}
VPN_DNS_SRV1=${VPN_DNS_SRV1:-10.2.1.1}
VPN_DNS_SRV2=${VPN_DNS_SRV2:-1.1.1.1}
VPN_POOL=${VPN_POOL:-10.2.231.0/24}
VPN_INTERNAL_SUBNET=${VPN_INTERNAL_SUBNET:-10.2.230.0/24}
CERT_DB=${CERT_DB:-sql:/etc/ipsec.d}
CA_NAME=${CA_NAME:-"IKEv2 VPN CA"}

# * export path
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# * error function
exiterr() { echo "Error: $1" >&2; exit 1; }

# * check if user is root
if [ "$(id -u)" != 0 ]; then
  exiterr "Script must be run as root. Try 'sudo bash $0'"
fi

# * check if openvz virtual environment
if [ -f /proc/user_beancounters ]; then
  exiterr "OpenVZ VPS is not supported."
fi

# * check if lxc missing /dev/ppp
if [ "$container" = "lxc" ] && [ ! -e /dev/ppp ]; then
  exiterr "/dev/ppp is missing. LXC containers require configuration."
fi

# * check os compatibility
OS_TYPE=$(lsb_release -si 2>/dev/null)
[ -z "$OS_TYPE" ] && [ -f /etc/os-release ] && OS_TYPE=$(. /etc/os-release && printf '%s' "$ID")
case $OS_TYPE in
  [Dd]ebian|[Uu]buntu)
    OS_TYPE=$(echo "$OS_TYPE" | tr '[:upper:]' '[:lower:]')
    OS_VER=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
    if [ "$OS_VER" = 8 ] || [ "$OS_VER" = 9 ] || [ "$OS_VER" = "stretchsid" ] || [ "$OS_VER" = "bustersid" ]; then
      exiterr "This script requires Debian >= 10 or Ubuntu >= 20.04."
    fi
    if [ "$OS_VER" = "trixiesid" ] && [ -f /etc/os-release ] && [ "$(. /etc/os-release && printf '%s' "$VERSION_ID")" = "24.10" ]; then
      exiterr "This script does not support Ubuntu 24.10. You may use e.g. Ubuntu 24.04 LTS instead."
    fi
    ;;
  *)
    exiterr "This script only supports Debian or Ubuntu."
    ;;
esac

# * check network interface
NET_IFACE=$(ip route show default | grep -oP '(?<=dev )[^ ]+')
[ -z "$NET_IFACE" ] && exiterr "Could not detect the default network interface."

# * wait for apt to be available
COUNT=0
APT_LK=/var/lib/apt/lists/lock
PKG_LK=/var/lib/dpkg/lock
while fuser "$APT_LK" "$PKG_LK" >/dev/null 2>&1 || lsof "$APT_LK" >/dev/null 2>&1 || lsof "$PKG_LK" >/dev/null 2>&1; do
  [ "$COUNT" = 0 ] && echo "## Waiting for apt to be available..."
  [ "$COUNT" -ge 100 ] && exiterr "Could not get apt/dpkg lock."
  COUNT=$((COUNT+1))
  printf '%s' '.'
  sleep 3
done

# * update apt cache
echo "## Installing packages required for setup..."
export DEBIAN_FRONTEND=noninteractive
apt-get -yqq update || apt-get -yqq update || exiterr "'apt-get update' failed."

# * install required packages
apt-get -yqq install wget dnsutils openssl iptables iproute2 gawk grep sed net-tools >/dev/null || exiterr "'apt-get install' failed."

# * install vpn packages
echo "## Installing packages required for the VPN..."
P1=libcurl4-nss-dev
[ "$OS_VER" = "trixiesid" ] && P1=libcurl4-gnutls-dev
apt-get -yqq install libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
  $P1 flex bison gcc make libnss3-tools libevent-dev libsystemd-dev uuid-runtime ppp xl2tpd >/dev/null || exiterr "'apt-get install' failed."

# * install fail2ban
echo "## Installing fail2ban to protect SSH..."
apt-get -yqq install fail2ban >/dev/null

# * determine libreswan version
SWAN_VER=5.2
BASE_URL="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
SWAN_VER_URL="$BASE_URL/v1-$OS_TYPE-$OS_VER-swanver"
SWAN_VER_LATEST=$(wget -t 2 -T 10 -qO- "$SWAN_VER_URL" | head -n 1)
if printf '%s' "$SWAN_VER_LATEST" | grep -Eq '^([3-9]|[1-9][0-9]{1,2})(\.([0-9]|[1-9][0-9]{1,2})){1,2}$'; then
  SWAN_VER="$SWAN_VER_LATEST"
fi

# * download and compile libreswan
echo "## Downloading Libreswan..."
cd /opt/src || mkdir -p /opt/src && cd /opt/src
SWAN_FILE="libreswan-$SWAN_VER.tar.gz"
SWAN_URL1="https://github.com/libreswan/libreswan/archive/v$SWAN_VER.tar.gz"
SWAN_URL2="https://download.libreswan.org/$SWAN_FILE"
wget -t 3 -T 30 -q -O "$SWAN_FILE" "$SWAN_URL1" || wget -t 3 -T 30 -q -O "$SWAN_FILE" "$SWAN_URL2" || exiterr "Failed to download Libreswan."
rm -rf "/opt/src/libreswan-$SWAN_VER"
tar xzf "$SWAN_FILE" && rm -f "$SWAN_FILE"

# * compile and install libreswan
echo "## Compiling and installing Libreswan..."
cd "libreswan-$SWAN_VER" || exiterr "Libreswan folder not found."
cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS=-w -s
USE_DNSSEC=false
USE_DH2=true
USE_NSS_KDF=false
FINALNSSDIR=/etc/ipsec.d
NSSDIR=/etc/ipsec.d
EOF
if ! grep -qs IFLA_XFRM_LINK /usr/include/linux/if_link.h; then
  echo "USE_XFRM_INTERFACE_IFLA_HEADER=true" >> Makefile.inc.local
fi
NPROCS=$(grep -c ^processor /proc/cpuinfo)
[ -z "$NPROCS" ] && NPROCS=1
make "-j$((NPROCS+1))" -s base >/dev/null && make -s install-base >/dev/null || exiterr "Failed to compile Libreswan."

# * configure ipsec
echo "## Creating VPN configuration..."
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
  ikev1-policy=accept
  virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!$VPN_POOL
  uniqueids=no

include /etc/ipsec.d/*.conf
EOF

# * set ipsec psk
echo "%any  %any  : PSK \"$VPN_IPSEC_PSK\"" > /etc/ipsec.secrets

# * update sysctl settings
echo "## Updating sysctl settings..."
if ! grep -qs "hwdsl2 VPN script" /etc/sysctl.conf; then
  cat >> /etc/sysctl.conf <<EOF

# Added by hwdsl2 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536

net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$NET_IFACE.send_redirects = 0
net.ipv4.conf.$NET_IFACE.rp_filter = 0

net.core.wmem_max = 16777216
net.core.rmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
EOF
  if modprobe -q tcp_bbr \
    && printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V \
    && [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
    cat >> /etc/sysctl.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  fi
fi

# * update iptables rules
echo "## Updating IPTables rules..."
IPT_FILE=/etc/iptables.rules
IPT_FILE2=/etc/iptables/rules.v4
service fail2ban stop >/dev/null 2>&1
IPI='iptables -I INPUT'
IPF='iptables -I FORWARD'
IPP='iptables -t nat -I POSTROUTING'
RES='RELATED,ESTABLISHED'
VPN_POOL_CIDR=$(echo $VPN_POOL | cut -d/ -f1)/$(echo $VPN_POOL | cut -d/ -f2)
$IPI 1 -m conntrack --ctstate INVALID -j DROP
$IPI 2 -m conntrack --ctstate "$RES" -j ACCEPT
$IPI 3 -p udp -m multiport --dports 500,4500 -j ACCEPT
$IPF 1 -m conntrack --ctstate INVALID -j DROP
$IPF 2 -i "$NET_IFACE" -o ppp+ -m conntrack --ctstate "$RES" -j ACCEPT
$IPF 3 -i ppp+ -o "$NET_IFACE" -j ACCEPT
$IPF 4 -i ppp+ -o ppp+ -j ACCEPT
$IPF 5 -i "$NET_IFACE" -d "$VPN_POOL_CIDR" -m conntrack --ctstate "$RES" -j ACCEPT
$IPF 6 -s "$VPN_POOL_CIDR" -o "$NET_IFACE" -j ACCEPT
$IPF 7 -s "$VPN_POOL_CIDR" -o ppp+ -j ACCEPT
iptables -A FORWARD -j DROP
$IPP -s "$VPN_POOL_CIDR" -o "$NET_IFACE" -j MASQUERADE
echo "# Modified by VPN script" > "$IPT_FILE"
iptables-save >> "$IPT_FILE"
if [ -f "$IPT_FILE2" ]; then
  cp -f "$IPT_FILE" "$IPT_FILE2"
fi

# * config iptables persistence
mkdir -p /etc/network/if-pre-up.d
cat > /etc/network/if-pre-up.d/iptablesload <<'EOF'
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
EOF
chmod +x /etc/network/if-pre-up.d/iptablesload

# * setup systemd service for iptables
if [ -f /usr/sbin/netplan ]; then
  mkdir -p /etc/systemd/system
  cat > /etc/systemd/system/load-iptables-rules.service <<'EOF'
[Unit]
Description = Load /etc/iptables.rules
DefaultDependencies=no

Before=network-pre.target
Wants=network-pre.target

Wants=systemd-modules-load.service local-fs.target
After=systemd-modules-load.service local-fs.target

[Service]
Type=oneshot
ExecStart=/etc/network/if-pre-up.d/iptablesload

[Install]
WantedBy=multi-user.target
EOF
  systemctl enable load-iptables-rules 2>/dev/null
fi

# * enable services on boot
echo "## Enabling services on boot..."
for SVC in fail2ban ipsec; do
  update-rc.d "$SVC" enable >/dev/null 2>&1
  systemctl enable "$SVC" 2>/dev/null
done

# * setup rc.local
if ! grep -qs "Added for VPN script" /etc/rc.local; then
  if [ -f /etc/rc.local ]; then
    sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
  else
    echo '#!/bin/sh' > /etc/rc.local
  fi
  RC_DELAY=15
  if uname -m | grep -qi '^arm'; then
    RC_DELAY=60
  fi
  cat >> /etc/rc.local <<EOF

# Added for VPN script
(sleep $RC_DELAY
service ipsec restart
echo 1 > /proc/sys/net/ipv4/ip_forward)&
exit 0
EOF
fi

# * setup ikev2 config
echo "## Creating IKEv2 configuration..."
IKEV2_CONF="/etc/ipsec.d/ikev2.conf"
XAUTH_POOL="$(echo $VPN_POOL | cut -d/ -f1 | sed 's/\.[0-9]*$//')"
XAUTH_POOL="${XAUTH_POOL}.10-${XAUTH_POOL}.250"

cat > "$IKEV2_CONF" <<EOF
conn ikev2-cp
  left=%defaultroute
  leftcert=$VPN_NAME
  leftsendcert=always
  leftsubnet=$VPN_INTERNAL_SUBNET
  leftrsasigkey=%cert
  right=%any
  rightid=%fromcert
  rightaddresspool=$XAUTH_POOL
  rightca=%same
  rightrsasigkey=%cert
  narrowing=yes
  dpddelay=30
  retransmit-timeout=300s
  dpdaction=clear
  auto=add
  ikev2=insist
  rekey=no
  pfs=no
  ike=aes_gcm_c_256-hmac_sha2_256-ecp_256,aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1
  phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes128-sha2,aes256-sha2
  ikelifetime=24h
  salifetime=24h
  encapsulation=yes
  leftid=@$VPN_NAME
  modecfgdns="$VPN_DNS_SRV1 $VPN_DNS_SRV2"
  mobike=yes
EOF

# * create ca and server certificates
echo "## Generating CA and server certificates..."
certutil -z <(head -c 1024 /dev/urandom) \
  -S -x -n "$CA_NAME" \
  -s "O=IKEv2 VPN,CN=$CA_NAME" \
  -k rsa -g 3072 -v 120 \
  -d "$CERT_DB" -t "CT,," -2 >/dev/null 2>&1 <<ANSWERS
y

N
ANSWERS

# * create server certificate
certutil -z <(head -c 1024 /dev/urandom) \
  -S -c "$CA_NAME" -n "$VPN_NAME" \
  -s "O=IKEv2 VPN,CN=$VPN_NAME" \
  -k rsa -g 3072 -v 120 \
  -d "$CERT_DB" -t ",," \
  --keyUsage digitalSignature,keyEncipherment \
  --extKeyUsage serverAuth \
  --extSAN "dns:$VPN_NAME" >/dev/null 2>&1 || exiterr "Failed to create server certificate."

# * start services
echo "## Starting services..."
sysctl -e -q -p
chmod +x /etc/rc.local
chmod 600 /etc/ipsec.secrets
mkdir -p /run/pluto
service fail2ban restart 2>/dev/null
service ipsec restart 2>/dev/null

# * show completion message
echo "================================================"
echo 
echo "IKEv2 VPN setup complete!"
echo 
echo "Server: $VPN_NAME"
echo "IPsec PSK: $VPN_IPSEC_PSK"
echo "Client address pool: $VPN_POOL"
echo "DNS servers: $VPN_DNS_SRV1, $VPN_DNS_SRV2"
echo 
echo "================================================"

exit 0