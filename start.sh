#!/bin/sh

ACME_SH_EMAIL=${ACME_SH_EMAIL:-dev@inboundparse.com}
DOMAIN=${MXDOMAIN:-mx.inboundparse.com}
DNS_API=${DNS_API:-dns_cf}

# Validate required environment variables for Cloudflare DNS
if [ "${DNS_API}" = "dns_cf" ]; then
    if [ -z "${CF_Token}" ] || [ -z "${CF_Zone_ID}" ]; then
        echo "ERROR: CF_Token and CF_Zone_ID are required when using dns_cf API"
        echo "Please set these environment variables in your .env file"
        exit 1
    fi
fi

echo "Starting with configuration:"
echo "  Domain: ${DOMAIN}"
echo "  DNS API: ${DNS_API}"
echo "  ACME Email: ${ACME_SH_EMAIL}"

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
    if ! acme.sh --home /cert --update-account --accountemail ${ACME_SH_EMAIL}; then
        echo "ERROR: Failed to set up ACME account"
        exit 1
    fi
    echo "Requesting certificates for ${DOMAIN} using ${DNS_API}"
    if ! acme.sh --home /cert --issue -d "${DOMAIN}" --dns "${DNS_API}" --server letsencrypt --log; then
        echo "ERROR: Failed to issue certificate for ${DOMAIN}"
        echo "Check your DNS API credentials and domain configuration"
        exit 1
    fi
fi

# Check if certificates are already issued and install them
if acme.sh --home /cert --list | grep -q "${DOMAIN}"; then
    echo "Certificate for ${DOMAIN} found, installing..."
    if ! acme.sh --home /cert --install-cert -d "${DOMAIN}" \
        --cert-file /cert/cert.pem \
        --key-file /cert/key.pem \
        --fullchain-file /cert/fullchain.pem; then
        echo "ERROR: Failed to install existing certificate for ${DOMAIN}"
        echo "Starting server without SSL certificates..."
    fi
else
    echo "No certificate found for ${DOMAIN}, attempting to issue..."
    if acme.sh --home /cert --issue -d "${DOMAIN}" --dns "${DNS_API}" --server letsencrypt --log; then
        echo "Certificate issued successfully, installing..."
        if ! acme.sh --home /cert --install-cert -d "${DOMAIN}" \
            --cert-file /cert/cert.pem \
            --key-file /cert/key.pem \
            --fullchain-file /cert/fullchain.pem; then
            echo "ERROR: Failed to install newly issued certificate for ${DOMAIN}"
            echo "Starting server without SSL certificates..."
        fi
    else
        echo "Failed to issue certificate for ${DOMAIN}"
        echo "Check your DNS API credentials and domain configuration"
        echo "Starting server without SSL certificates..."
    fi
fi

# Upgrade and list certificates
echo 'Upgrading and listing certificates'
acme.sh --home /cert --upgrade --auto-upgrade
acme.sh --home /cert --list


# Wait for certificates to be available (with timeout)
echo "Checking for certificates..."
CERT_WAIT_COUNT=0
CERT_WAIT_MAX=30  # 5 minutes max wait

while [ ! -f /cert/cert.pem ] || [ ! -f /cert/key.pem ]; do
    if [ $CERT_WAIT_COUNT -ge $CERT_WAIT_MAX ]; then
        echo "Timeout waiting for certificates. Starting server without SSL..."
        break
    fi
    echo "Still waiting for certificates... (${CERT_WAIT_COUNT}/${CERT_WAIT_MAX})"
    sleep 10
    CERT_WAIT_COUNT=$((CERT_WAIT_COUNT + 1))
done

if [ -f /cert/cert.pem ] && [ -f /cert/key.pem ]; then
    echo "Certificates found, starting SMTP server with SSL..."
else
    echo "Starting SMTP server without SSL certificates..."
fi

# Start SMTP server with environment variables
./inboundparse \
    -webhook="${WEBHOOK_URL}" \
    -enable-spf="${ENABLE_SPF}" \
    -enable-dkim="${ENABLE_DKIM}" \
    -enable-dmarc="${ENABLE_DMARC}" \
    -cert-file="${CERT_FILE}" \
    -key-file="${KEY_FILE}" \
    -verbose="${VERBOSE}"
    