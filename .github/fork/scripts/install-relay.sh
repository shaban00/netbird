#!/usr/bin/env bash
#
# Installs a standalone NetBird relay (with STUN) using Docker Compose, with a
# Let's Encrypt certificate obtained by the relay itself.
#
# Interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-relay.sh | bash
#
# Non-interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-relay.sh | \
#     NETBIRD_RELAY_DOMAIN=relay1.netbird.example.com \
#     NETBIRD_RELAY_AUTH_SECRET='the authSecret from the NetBird server config.yaml' \
#     bash
#
# Without NETBIRD_RELAY_AUTH_SECRET a new secret is generated; the NetBird
# server must then be configured with it (the installer prints how).

set -euo pipefail

RELAY_IMAGE="${RELAY_IMAGE:-@@DOCKERHUB_NAMESPACE@@/netbird-relay:@@IMAGE_TAG@@}"
RELAY_PORT="${NETBIRD_RELAY_PORT:-443}"
STUN_PORT="${NETBIRD_STUN_PORT:-3478}"

log() {
  printf '\n%s\n' "$*"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

check_dependencies() {
  command -v docker >/dev/null 2>&1 || die "Docker is required."
  command -v openssl >/dev/null 2>&1 || die "openssl is required."
  command -v curl >/dev/null 2>&1 || die "curl is required."

  if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
  else
    die "Docker Compose is required."
  fi
}

tty_available() {
  [[ "${NETBIRD_NON_INTERACTIVE:-}" == "true" ]] && return 1
  { true </dev/tty; } 2>/dev/null
}

# read_value ENV_NAME PROMPT [DEFAULT] [OPTIONAL]
# Uses $ENV_NAME when set, otherwise asks on the terminal. In non-interactive
# mode the default is used; without one the value is required unless OPTIONAL.
read_value() {
  local env_name="$1" prompt="$2" default="${3:-}" optional="${4:-}"
  local value="${!env_name:-}"

  if [[ -n "$value" ]]; then
    printf '%s' "$value"
    return
  fi

  if tty_available; then
    if [[ -n "$default" ]]; then
      printf "%s [%s]: " "$prompt" "$default" >/dev/tty
    else
      printf "%s: " "$prompt" >/dev/tty
    fi
    read -r value </dev/tty
    printf '%s' "${value:-$default}"
    return
  fi

  if [[ -n "$default" || -n "$optional" ]]; then
    printf '%s' "$default"
    return
  fi

  die "$env_name is required in non-interactive mode."
}

validate_domain() {
  local domain="$1"

  [[ -n "$domain" ]] || die "Relay domain cannot be empty."
  [[ "$domain" != *"://"* ]] ||
    die "Relay domain must be a hostname only, for example relay1.netbird.example.com."
  [[ "$domain" != */* && "$domain" != *:* ]] || die "Relay domain must not contain a path or port."
  [[ ${#domain} -le 253 ]] || die "Relay domain is too long."
  [[ "$domain" == *.* ]] ||
    die "Relay domain must be a fully-qualified domain name, for example relay1.netbird.example.com."
  [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] ||
    die "Invalid relay domain: $domain"

  # Let's Encrypt also requires the domain to resolve publicly to this server.
  if command -v getent >/dev/null 2>&1; then
    getent ahosts "$domain" >/dev/null 2>&1 || die "Relay domain does not resolve in DNS: $domain"
  elif command -v dig >/dev/null 2>&1; then
    [[ -n "$(dig +short "$domain" A "$domain" AAAA 2>/dev/null)" ]] ||
      die "Relay domain does not resolve in DNS: $domain"
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$domain" >/dev/null 2>&1 || die "Relay domain does not resolve in DNS: $domain"
  else
    echo "WARNING: getent, dig, and nslookup are unavailable; skipping DNS validation." >&2
  fi
}

configure() {
  # The relay obtains its certificate with the TLS-ALPN challenge, which Let's
  # Encrypt only performs on port 443, and it has no separate challenge port.
  [[ "$RELAY_PORT" == "443" ]] ||
    die "NETBIRD_RELAY_PORT must be 443: the relay's Let's Encrypt certificate is issued over port 443."

  RELAY_DOMAIN="$(read_value NETBIRD_RELAY_DOMAIN "Relay domain (for example relay1.netbird.example.com)")"
  validate_domain "$RELAY_DOMAIN"

  RELAY_AUTH_SECRET="$(read_value NETBIRD_RELAY_AUTH_SECRET \
    "Relay auth secret (the authSecret in the NetBird server's config.yaml; leave empty to generate one)" "" optional)"
  SECRET_GENERATED=false
  if [[ -z "$RELAY_AUTH_SECRET" ]]; then
    RELAY_AUTH_SECRET="$(openssl rand -base64 32 | tr -d '=')"
    SECRET_GENERATED=true
  fi
}

check_existing() {
  if [[ -e docker-compose.yml || -e docker-compose.yaml || -e .env ]]; then
    echo "Relay configuration files already exist in the current directory." >&2
    echo "" >&2
    echo "Existing files:" >&2
    [[ -e docker-compose.yml ]] && echo "  docker-compose.yml" >&2
    [[ -e docker-compose.yaml ]] && echo "  docker-compose.yaml" >&2
    [[ -e .env ]] && echo "  .env" >&2
    echo "" >&2
    echo "Move or remove the existing files before running this installer." >&2
    exit 1
  fi
}

render_files() {
  log "Generating configuration files..."

  cat > docker-compose.yml <<EOF
services:
  relay:
    image: ${RELAY_IMAGE}
    container_name: netbird-relay
    restart: unless-stopped
    ports:
      - '${RELAY_PORT}:${RELAY_PORT}'
      - '${STUN_PORT}:${STUN_PORT}/udp'
    env_file:
      - .env
    volumes:
      - relay:/data
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

volumes:
  relay:
    name: netbird-relay
    driver: local
EOF

  (
    umask 077
    cat > .env <<EOF
# NetBird Relay

NB_LOG_LEVEL=info
# Relay listener
NB_LISTEN_ADDRESS=:${RELAY_PORT}
# Public address advertised to NetBird peers
NB_EXPOSED_ADDRESS=rels://${RELAY_DOMAIN}:${RELAY_PORT}
# Relay authentication secret.
# The NetBird server must be configured with the same secret.
NB_AUTH_SECRET=${RELAY_AUTH_SECRET}
# Let's Encrypt
NB_LETSENCRYPT_DOMAINS=${RELAY_DOMAIN}
NB_LETSENCRYPT_DATA_DIR=/data/letsencrypt
# STUN
NB_ENABLE_STUN=true
NB_STUN_PORTS=${STUN_PORT}
EOF
  )
}

wait_for_container() {
  log "Waiting for the relay container to start..."

  local retries=0 running
  while true; do
    running="$(docker inspect netbird-relay --format '{{.State.Running}}' 2>/dev/null || true)"
    if [[ "$running" == "true" ]]; then
      echo "Relay container is running."
      return 0
    fi

    retries=$((retries + 1))
    if [[ "$retries" -ge 30 ]]; then
      echo "" >&2
      echo "Relay failed to start. Recent logs:" >&2
      docker logs --tail=50 netbird-relay 2>&1 || true
      die "Relay did not start successfully."
    fi
    sleep 2
  done
}

verify_tls_certificate() {
  local retries=0 max_retries=30

  # A successful request means the certificate was issued and is trusted. HTTP
  # error statuses do not matter here (no --fail).
  while ! curl --silent --show-error --output /dev/null --connect-timeout 5 --max-time 10 \
    "https://${RELAY_DOMAIN}/"; do
    retries=$((retries + 1))
    if [[ "$retries" -ge "$max_retries" ]]; then
      echo "" >&2
      echo "Unable to verify TLS for https://${RELAY_DOMAIN}/" >&2
      echo "" >&2
      echo "Recent relay logs:" >&2
      docker logs --tail=50 netbird-relay 2>&1 || true
      echo "" >&2
      die "Let's Encrypt certificate provisioning or TLS verification failed."
    fi
    echo "Waiting for certificate provisioning... (${retries}/${max_retries})"
    sleep 2
  done
  echo "TLS certificate is valid and trusted."
}

start_relay() {
  log "Starting NetBird Relay..."
  $DOCKER_COMPOSE up -d
  wait_for_container
  verify_tls_certificate
}

show_results() {
  local secret_note="the auth secret you provided"
  if [[ "$SECRET_GENERATED" == "true" ]]; then
    secret_note="a newly generated auth secret (stored as NB_AUTH_SECRET in $(pwd)/.env)"
  fi

  cat <<EOF

==========================================
NetBird Relay installation complete
==========================================

Relay address:  rels://${RELAY_DOMAIN}:${RELAY_PORT}
STUN address:   stun:${RELAY_DOMAIN}:${STUN_PORT}

Open ports: ${RELAY_PORT}/tcp and ${STUN_PORT}/udp

This relay uses ${secret_note}.

Use it from the NetBird server: add to the server section of its config.yaml
(this replaces the server's built-in relay and STUN), then restart the server:

  relays:
    addresses:
      - "rels://${RELAY_DOMAIN}:${RELAY_PORT}"
    credentialsTTL: "24h"
    secret: "${RELAY_AUTH_SECRET}"
  stuns:
    - uri: "stun:${RELAY_DOMAIN}:${STUN_PORT}"

The secret must be identical on the server and on every relay listed there.

Browser client / browser SSH: add the relay's WebSocket origin to
NETBIRD_CSP in the dashboard environment (space-separated with any existing
entries), then restart the dashboard:

  NETBIRD_CSP=wss://${RELAY_DOMAIN}

==========================================
EOF
}

main() {
  check_dependencies
  check_existing
  configure
  render_files
  start_relay
  show_results
}

main "$@"
