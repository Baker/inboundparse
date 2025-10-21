#!/bin/sh

ACME_SH_EMAIL=${ACME_SH_EMAIL:-dev@inboundparse.com}
DOMAIN=${MXDOMAIN:-mx.inboundparse.com}
DNS_API=${DNS_API:-dns_cf}

# Check if acme.sh is installed, if not install it
if ! command -v acme.sh >/dev/null 2>&1; then
    echo 'acme.sh not found, installing...'
    curl https://get.acme.sh | sh -s email=${ACME_SH_EMAIL}
    # Source the acme.sh environment
    . ~/.acme.sh/acme.sh.env
fi

# Set up account on first startup
if [ ! -f /cert/account.conf ]; then
    echo "First startup - setting up account ${ACME_SH_EMAIL}"
    acme.sh --home /cert --update-account --accountemail ${ACME_SH_EMAIL}
    echo "Requesting certificates for ${DOMAIN} using ${DNS_API}"
    acme.sh --home /cert --issue -d "${DOMAIN}" --dns "${DNS_API}" --server letsencrypt --log
fi

# Install certificates if not already present
if [ ! -f /cert/fullchain.pem ]; then
    acme.sh --install-cert -d "${DOMAIN}" \
        --cert-file /cert/cert.pem \
        --key-file /cert/key.pem \
        --fullchain-file /cert/fullchain.pem
fi

# Upgrade and list certificates
echo 'Upgrading and listing certificates'
acme.sh --upgrade --auto-upgrade
acme.sh --list


# Wait for certificates to be available
echo "Waiting for certificates..."
while [ ! -f /cert/cert.pem ] || [ ! -f /cert/key.pem ]; do
    echo "Still waiting for certificates..."
    sleep 10
done

echo "Certificates found, starting SMTP server..."

# Start SMTP server with environment variables
./inboundparse \
    -webhook="${WEBHOOK_URL}" \
    -enable-spf="${ENABLE_SPF}" \
    -enable-dkim="${ENABLE_DKIM}" \
    -enable-dmarc="${ENABLE_DMARC}" \
    -cert-file="${CERT_FILE}" \
    -key-file="${KEY_FILE}" \
    -verbose="${VERBOSE}"
    