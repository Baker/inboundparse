#!/bin/sh
# Request a Let's Encrypt certificate when DNS credentials are present, then
# start SMTP. Issuance is optional: a missing credential or a failed request
# must not stop the server. It listens in plaintext until a certificate exists.
set -eu

DOMAIN=${MXDOMAIN:-${SERVER_NAME:-mx.inboundparse.com}}
DNS_API=${DNS_API:-dns_cf}
ACME_SH_EMAIL=${ACME_SH_EMAIL:-devnull@localhost}
CERT_DIR=/cert
CERT_PATH="${CERT_DIR}/cert.pem"
KEY_PATH="${CERT_DIR}/key.pem"
FULLCHAIN_PATH="${CERT_DIR}/fullchain.pem"

mkdir -p "${CERT_DIR}"

# An empty file left by a failed install is not a certificate.
if [ -f "${CERT_PATH}" ] && [ ! -s "${CERT_PATH}" ]; then
    rm -f "${CERT_PATH}"
fi
if [ -f "${KEY_PATH}" ] && [ ! -s "${KEY_PATH}" ]; then
    rm -f "${KEY_PATH}"
fi
if [ -f "${FULLCHAIN_PATH}" ] && [ ! -s "${FULLCHAIN_PATH}" ]; then
    rm -f "${FULLCHAIN_PATH}"
fi

# Cloudflare is the default DNS provider. Other acme.sh DNS APIs bring their
# own credentials, so only dns_cf is checked here.
dns_ready() {
    if [ "${DNS_API}" != "dns_cf" ]; then
        return 0
    fi
    if [ -n "${CF_Token:-}" ] && [ -n "${CF_Zone_ID:-}" ]; then
        return 0
    fi
    return 1
}

install_cert() {
    acme.sh --home "${CERT_DIR}" --install-cert -d "${DOMAIN}" \
        --cert-file "${CERT_PATH}" \
        --key-file "${KEY_PATH}" \
        --fullchain-file "${FULLCHAIN_PATH}"
}

if dns_ready; then
    if ! command -v acme.sh >/dev/null 2>&1; then
        echo "acme.sh is not installed. Skipping certificate request."
    else
        echo "Certificate configuration:"
        echo "  Domain: ${DOMAIN}"
        echo "  DNS API: ${DNS_API}"
        echo "  ACME Email: ${ACME_SH_EMAIL}"

        # Pin the CA to Let's Encrypt. ZeroSSL asks for an external account
        # binding that this image does not have.
        acme.sh --home "${CERT_DIR}" --set-default-ca --server letsencrypt || true
        if [ ! -f "${CERT_DIR}/account.conf" ]; then
            acme.sh --home "${CERT_DIR}" --register-account -m "${ACME_SH_EMAIL}" --server letsencrypt || true
        fi

        if [ ! -s "${CERT_PATH}" ] || [ ! -s "${KEY_PATH}" ]; then
            # A partial acme.sh directory makes the next --issue refuse to run.
            if [ ! -s "${CERT_DIR}/${DOMAIN}_ecc/${DOMAIN}.cer" ]; then
                rm -rf "${CERT_DIR}/${DOMAIN}_ecc"
            fi
            echo "Requesting certificate for ${DOMAIN}"
            if acme.sh --home "${CERT_DIR}" --issue -d "${DOMAIN}" --dns "${DNS_API}" --server letsencrypt; then
                if ! install_cert; then
                    echo "Certificate issued, but installing it failed."
                fi
            else
                echo "Certificate request failed."
            fi
        else
            echo "Certificate files found. Renewing if due."
            acme.sh --home "${CERT_DIR}" --cron || true
            install_cert || true
        fi
    fi
else
    echo "Cloudflare DNS credentials are not set. Skipping certificate request."
fi

# A non-empty file is not necessarily a certificate. A partial install leaves
# garbage that tls.LoadX509KeyPair rejects, and that rejection exits the process.
cert_pair_ok() {
    cert="$1"
    key="$2"
    if [ ! -s "${cert}" ] || [ ! -s "${key}" ]; then
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout >/dev/null 2>&1; then
        return 1
    fi
    if ! openssl pkey -in "${key}" -noout >/dev/null 2>&1; then
        return 1
    fi
    cert_pub=$(openssl x509 -in "${cert}" -noout -pubkey 2>/dev/null) || return 1
    key_pub=$(openssl pkey -in "${key}" -pubout 2>/dev/null) || return 1
    [ "${cert_pub}" = "${key_pub}" ]
}

# Prefer the chain file so SMTP clients can validate without fetching it.
# The image ENV may already point CERT_FILE at a path that does not exist;
# unset it unless the files on disk are a matching pair.
if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is not installed. Starting SMTP without STARTTLS."
    unset CERT_FILE
    unset KEY_FILE
elif cert_pair_ok "${FULLCHAIN_PATH}" "${KEY_PATH}"; then
    echo "Starting SMTP with STARTTLS."
    export CERT_FILE="${FULLCHAIN_PATH}"
    export KEY_FILE="${KEY_PATH}"
elif cert_pair_ok "${CERT_PATH}" "${KEY_PATH}"; then
    echo "Starting SMTP with STARTTLS."
    export CERT_FILE="${CERT_PATH}"
    export KEY_FILE="${KEY_PATH}"
else
    if [ -s "${FULLCHAIN_PATH}" ] || [ -s "${CERT_PATH}" ] || [ -s "${KEY_PATH}" ]; then
        echo "Certificate files are not a usable pair. Starting SMTP without STARTTLS."
    else
        echo "Starting SMTP without STARTTLS."
    fi
    unset CERT_FILE
    unset KEY_FILE
fi

# The DNS token is only needed to issue the certificate. The mail process
# parses untrusted SMTP and must not keep a Cloudflare credential.
unset CF_Token CF_Zone_ID

# Volumes mounted at /cert are root-owned. Issue as root, then drop to the
# unprivileged user once that user can read the directory.
if [ "$(id -u)" -eq 0 ] && command -v su-exec >/dev/null 2>&1 && id inboundparse >/dev/null 2>&1; then
    if chown -R inboundparse:inboundparse "${CERT_DIR}"; then
        exec su-exec inboundparse:inboundparse /usr/local/bin/inboundparse
    fi
    echo "Could not change ownership of ${CERT_DIR}. Starting SMTP as root."
fi

exec /usr/local/bin/inboundparse
