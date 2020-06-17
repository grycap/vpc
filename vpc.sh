#!/bin/bash

# Set the default values

# The name of the server (it is not too important, except if you want to have multiple openvpn servers in the same host)
SERVERNAME=openvpnserver

# The host in which the server will listen
VPN_PORT=10443

# The IP address range for the VPN
VPN_CIDR=172.$((16+$(($RANDOM%16)))).$(($RANDOM%255)).0/24

# The name of the client (not much important except if you want to privide access to multiple users to the VPN)
CLIENTNAME=client

# 
SKIPNAT=false

# Function that converts the CIDR segment to the classic mask (e.g. 255.255.255.0)
function cidrtomask {
    local MASK
    MASK=0x"$(printf "%08x" $(( $((0xffffffff << $((32 - $1)) )) & 0xffffffff )) )" || return 1
    printf "%d.%d.%d.%d\n" 0x${MASK:2:2} 0x${MASK:4:2} 0x${MASK:6:2} 0x${MASK:8:2}
    return 0
}

# Function that converts an arbitraty IP address to the proper CIDR notation (i.e. with zeros in the bits that are out of the mask)
#   e.g. 192.168.1.1/24 => 192.168.1.0/24
function iptonet {
        local IP MASK EXTRA NET NBITS
        IFS=/ read IP NBITS EXTRA <<< "$1"
        [ "$EXTRA" != "" ] && return 1
        [ "$NBITS" == "" ] && NBITS=32
        [ -z "${NBITS##*[!0-9]*}" ] && return 1
        IP=0x"$(printf "%02x%02x%02x%02x" ${IP//./ } 2> /dev/null)" || return 1
        MASK=0x"$(printf "%08x" $(( $((0xffffffff << $((32 - $NBITS)) )) & 0xffffffff )) )" || return 1
        NET=0x"$(printf "%08x" $(($IP & $MASK)) )" || return 1
        printf "%d.%d.%d.%d/%d\n" 0x${NET:2:2} 0x${NET:4:2} 0x${NET:6:2} 0x${NET:8:2} $NBITS
        return 0
}

# Function that detects whether two networks (expressed in CIDR notation) intersect or not
#   usage: netintersect CIDR1 CIDR2
function netintersect {
        local IP1 BITS1 MASK1 R1
        local IP2 BITS2 MASK2 R2
        IP1=${1%%/*}
        BITS1=${1##*/}
        IP2=${2%%/*}
        BITS2=${2##*/}
        IP1=0x"$(printf "%02x%02x%02x%02x" ${IP1//./ } 2> /dev/null)"
        IP2=0x"$(printf "%02x%02x%02x%02x" ${IP2//./ } 2> /dev/null)"
        MASK1=0x"$(printf "%08x" $(( $((0xffffffff << $((32 - $BITS1)) )) & 0xffffffff )) )"
        MASK2=0x"$(printf "%08x" $(( $((0xffffffff << $((32 - $BITS2)) )) & 0xffffffff )) )"
        R1=$(($((IP1 & $MASK1)) & MASK2))
        R2=$(($((IP2 & $MASK1)) & MASK2))
        [ "$R1" == "$R2" ] && return 0
        return 1
}

# Wrapper to exit with error
function exit1 {
    echo "$@" >&2
    exit 1
}

# Function that reads the next parameter in the variable with name passed as an argument
#   usage: readparam VARNAME
function readparam {
    CPARAM=$((CPARAM+1))
    if ((CPARAM<${#PARAMS[@]})); then
        read ${1} <<< "${PARAMS[$CPARAM]}"
    else
        exit1 "missing parameter for $COPTION"
    fi
}

# Display the help for the command
function usage {
    cat - <<EOT
    Usage: 
        ivpn.sh [ easyrsa | server <options> | client <subcommand> <options> ]
            easyrsa         -   installs the latest version of EasyRSA and prepares a new CA

            server          -   installs OpenVPN and configures it, by creating a new certificate, etc.
                                EasyRSA must be installed in /opt/easyrsa

                                This command also prepares the scripts to NAT to an internal private 
                                network, thus making the server act as a VPC server for the private
                                network.

            client
                new         -   Creates a new client configuration file to be used with openvpn command
                retrieve    -   Retrieves the configuration file to be used with openvpn for an existing
                                client
EOT
}

# Function that installs the latest version of easyrsa from the github repository. The installation
#   is left in /opt/EasyRSA<version> with a link in /opt/easyrsa
function easyrsa {
    if [ -e /opt/easyrsa ]; then
        exit1 "/opt/easyrsa already exists"
    fi
    cd /tmp

    # Get the current release and its URL from the github repo
    RELEASES="$(curl -X GET https://api.github.com/repos/OpenVPN/easy-rsa/releases)" || exit1 "could not obtain EasyRSA info"
    URL="$(echo "$RELEASES" | jq '.[0].assets[] | select(.content_type=="application/x-gzip") | .browser_download_url')" || exit1 "could not get information about EasyRSA version"
    URL="${URL:1:-1}"

    # Download the release file and untargzip it
    wget "$URL"
    FNAME="$(basename "$URL")"
    tar xfz "$FNAME"

    # Move EasyRSA to /opt and create the link /opt/easyrsa
    mkdir -p /opt
    mv "${FNAME%.*}" /opt
    cd /opt
    ln -s "${FNAME%.*}" easyrsa

    # Initialize the PKI and generate the diffie-hellman (DH) params
    cd /opt/easyrsa
    ./easyrsa --batch init-pki
    ./easyrsa --batch gen-dh
}

# Function that generates the client configuration file that includes the key and certificate embedded in it
function client_genfile {
    umask 0077
    CLIKEY="$(cat pki/private/"$CLIENTHASH".key)"
    CLICERT="$(cat pki/issued/"$CLIENTHASH".crt)"
    cd /etc/openvpn/$SERVERNAME
    TA="$(cat ta.key)"
    CA="$(cat ca.crt)"
    cat > $CLIENT_FILE <<EOT
client
dev tun
proto tcp
# remote <IP_ADDR> $VPN_PORT
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA512
key-direction 1
verb 3
<ca>
$CA
</ca>
<cert>
$CLICERT
</cert>
<key>
$CLIKEY
</key>
<tls-auth>
$TA
</tls-auth>
EOT
}

# Function that implements the option "client get"
function client_get {
    # There must exist the key
    [ -e pki/private/"$CLIENTHASH".key ] || exit1 "it does not exist a certificate for $CLIENTNAME"

    # Generate the file with the configuration for the client
    client_genfile
}

function client_new {
    # The key must not exist
    [ -e pki/private/"$CLIENTHASH".key ] && exit1 "a certificate for $CLIENTNAME already exists"

    # Generate client certificates
    ./easyrsa --batch --req-cn="$CLIENTNAME" gen-req "$CLIENTHASH" nopass 2> /dev/null > /dev/null
    ./easyrsa --batch sign-req client "$CLIENTHASH" 2>/dev/null > /dev/null

    # Generate the file with the configuration for the client
    client_genfile
}

function client {
    # Get the operation
    COP="${PARAMS[$CPARAM]}"
    CPARAM=$((CPARAM+1))

    # Get the parameters (they are common for each sub operation)
    while ((CPARAM<${#PARAMS[@]})); do
        COPTION=${PARAMS[$CPARAM]}
        case $COPTION in
            -n|--client-name)  readparam CLIENTNAME;;
            -s|--server-name)  readparam SERVERNAME;;
            -f|--file)         readparam CLIENT_FILE;;
            *)
                usage;;
        esac
        CPARAM=$((CPARAM+1))
    done    

    [ -z "${SERVERNAME##*[!0-9A-Za-z]*}" ] && exit1 "invalid name for server"
    [ "$CLIENT_FILE" == "-" ] && CLIENT_FILE=/dev/stdout

    # Get a hash for the name of the client
    CLIENTHASH="$(echo "$CLIENTNAME" | md5sum)"
    CLIENTHASH="${CLIENTHASH%% *}"

    # Set a default filename to output the client file
    [ "$CLIENT_FILE" == "" ] && CLIENT_FILE="$(pwd)/$CLIENTHASH.ovpn"

    # Check whether the folder for the server exists or not (the CA, ta.key, etc. files should be there)
    cd /etc/openvpn/$SERVERNAME  2> /dev/null || exit1 "could not find configuration for server $SERVERNAME"

    # Any command expect to be in /opt/easyrsa folder
    cd /opt/easyrsa 2> /dev/null || exit1 "easyrsa not found at folder /opt/easyrsa"

    case "$COP" in
        new)    client_new;;
        get)    client_get;;
        revoke) exit1 "not implemented";;
        *)      usage;;
    esac
}

# Function that installs and configures the server
function server {
    while ((CPARAM<${#PARAMS[@]})); do
        COPTION=${PARAMS[$CPARAM]}
        case $COPTION in
            -n|--name)  readparam SERVERNAME;;
            -p|--port)  readparam VPN_PORT;;
            -v|--vpn-cidr)
                        readparam VPN_CIDR;;
            -i|--internal-cidr)
                        readparam PRIV_CIDR;;
            -s|--skip-nat)
                        SKIPNAT=true;;
            *)
                usage;;
        esac
        CPARAM=$((CPARAM+1))
    done

    # Check that the name for the server is valid (only letters and numbers)
    [ -z "${SERVERNAME##*[!0-9A-Za-z]*}" ] && exit1 "invalid name for server"
    VPN_CIDR=${VPN_CIDR:-x}
    PRIV_CIDR=${PRIV_CIDR:-x}

    # Check that the port is valid (only numbers)
    [ -z "${VPN_PORT##*[!0-9]*}" ] && exit1 "invalid port"

    # Check that the VPN CIDR is valid
    VPN_NET="$(iptonet $VPN_CIDR)" || exit1 "invalid CIDR for VPN"
    echo "VPN Network: $VPN_NET"
    VPN_BITS=${VPN_NET##*/}
    [ $VPN_BITS -ge 32 ] && exit1 "Net is too small (only 1 machine)"

    if [ "$SKIPNAT" != "true" ]; then
        # Check that the private network is valid
        PRIV_NET=$(iptonet $PRIV_CIDR) || exit1 "invalid CIDR for Private Network"
        echo "Private Network: $PRIV_NET"
        PRIV_BITS=${PRIV_NET##*/}
        [ $PRIV_BITS -ge 32 ] && exit1 "Net is too small (only 1 machine)"

        # Check that both networks (private and VPN) do intersect
        netintersect $PRIV_NET $VPN_NET && exit1 "Networks for VPN and Private Network intersect"

        # Find the device that has the private network (it must exist)
        while read IINFO; do
            IP="${IINFO#* }"
            ICIDR="${IP%% *}"
            IDEV="${IP##* }"
            NET="$(iptonet $IP)" || exit1 "failed to get IPs in the host"
            netintersect $NET $VPN_NET && exit1 "Networks for VPN ($NET) and $VPN_NET intersect"
            if netintersect $NET $PRIV_NET; then
                IINFO2="$(ip -4 a show $IDEV | grep inet)"
                IINFO2="$(echo $IINFO)"
                [ "$IINFO" != "$IINFO2" ] && exit1 "failed to guess private interface"
                PRIV_DEV="$IDEV"
            fi
        done <<< "$(ip -4 a | grep inet)"

        # If the private network does not exist, quit
        if [ "$PRIV_DEV" == "" ]; then
                exit1 "Could not find the private network $PRIV_NET or find the interface to which is assigned"
        fi
    fi

    # We'll need easyrsa to generate the certificates
    cd /opt/easyrsa 2> /dev/null || exit1 "easyrsa not found at folder /opt/easyrsa"

    # Install OpenVPN
    apt update
    apt install -y openvpn

    # Generate CA and generate OpenVPN server certificate, keys, etc.
    UUID=$(cat /proc/sys/kernel/random/uuid)
    ./easyrsa --batch --req-cn="vpc-${UUID%%-*}" build-ca nopass
    ./easyrsa --batch gen-req server nopass
    ./easyrsa --batch sign-req server server
    openvpn --genkey --secret ta.key

    # Copy the certificates and so on to a folder for the server
    mkdir /etc/openvpn/$SERVERNAME
    cp pki/dh.pem /etc/openvpn/$SERVERNAME
    cp pki/ca.crt /etc/openvpn/$SERVERNAME
    cp pki/private/server.key /etc/openvpn/$SERVERNAME
    cp pki/issued/server.crt /etc/openvpn/$SERVERNAME
    cp ta.key /etc/openvpn/$SERVERNAME
    mkdir -p /var/log/openvpn/$SERVERNAME

    # Generate server configuration
    cat > /etc/openvpn/$SERVERNAME.conf <<EOT
port $VPN_PORT
proto tcp
dev tun
ca /etc/openvpn/$SERVERNAME/ca.crt
cert /etc/openvpn/$SERVERNAME/server.crt
key /etc/openvpn/$SERVERNAME/server.key
dh /etc/openvpn/$SERVERNAME/dh.pem
server ${VPN_NET%%/*} $(cidrtomask ${VPN_NET##*/})
ifconfig-pool-persist /var/log/openvpn/$SERVERNAME/ipp.txt
keepalive 10 120
tls-auth /etc/openvpn/$SERVERNAME/ta.key 0
cipher AES-256-CBC
auth SHA512
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/$SERVERNAME/openvpn-status.log
log-append /var/log/openvpn/$SERVERNAME/openvpn.log
verb 3
explicit-exit-notify 0
EOT

    if [ "$SKIPNAT" != "true" ]; then
        cat >> /etc/openvpn/$SERVERNAME.conf <<EOT
push "route ${PRIV_NET%%/*} $(cidrtomask ${PRIV_NET##*/})"
EOT

        # Now prepare a folder for the nat scripts to the internal network
        mkdir -p /etc/openvpn/$SERVERNAME/scripts

        # Create the scripts that will nat to the internal network
        cat > /etc/openvpn/$SERVERNAME/scripts/donat.sh <<EOT
#!/bin/bash
sysctl net.ipv4.ip_forward=1
iptables -t nat -I POSTROUTING 1 -s $VPN_NET -o ${PRIV_DEV} -j MASQUERADE
exit 0
EOT
        cat > /etc/openvpn/$SERVERNAME/scripts/rmnat.sh <<EOT
#!/bin/bash
iptables -t nat -D POSTROUTING -s $VPN_NET -o ${PRIV_DEV} -j MASQUERADE
EOT
        chmod +x /etc/openvpn/$SERVERNAME/scripts/donat.sh
        chmod +x /etc/openvpn/$SERVERNAME/scripts/rmnat.sh

        # Create systemd service file that will enable nat (indeed this is the service that must be started to start NAT too)
        cat > /etc/openvpn/$SERVERNAME/scripts/vpcnat_$SERVERNAME.service <<EOT
[Unit]
Description=Nat rules to access the private network $PRIV_NET from VPN $VPN_NET
After=openvpn@$SERVERNAME.service
Wants=openvpn@$SERVERNAME.service
PartOf=openvpn@$SERVERNAME.service

[Service]
Type=oneshot
ExecStart=/etc/openvpn/$SERVERNAME/scripts/donat.sh
RemainAfterExit=true
ExecStop=/etc/openvpn/$SERVERNAME/scripts/rmnat.sh
StandardOutput=journal

[Install]
WantedBy=openvpn@$SERVERNAME.service
EOT

        # Show some instructions to enable the service
        cat <<EOT
Service file for systemd /etc/openvpn/$SERVERNAME/scripts/vpcnat_$SERVERNAME.service has been created

This file makes that masquerading is enabled from the VPN network to the private network once the OpenVPN server is started.

To automate this process, you can
- copy (or to move) the file to /etc/systemd/system/
- run systemctl daemon-reload
- run systemctl enable vpcnat_$SERVERNAME.service

When service openvpn@$SERVERNAME.service is started, the masquerading process will be triggered by running the script /etc/openvpn/$SERVERNAME/scripts/donat.sh
When the service is stopped, the script /etc/openvpn/$SERVERNAME/scripts/rmnat.sh will be triggered
EOT
    fi
}

# Check the main op
OP=$1
shift
PARAMS=("$@")
CPARAM=0
case $OP in
    server)
        server;;
    client)
        client;;
    easyrsa)
        easyrsa;;
    *)
        usage;;
esac