#!/usr/bin/env bash
#
# Installs a standalone NetBird Signal server using Docker Compose, with a
# Let's Encrypt certificate obtained by Signal itself.
#
# Interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-signal.sh | bash
#
# Non-interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-signal.sh | \
#     NETBIRD_SIGNAL_DOMAIN=signal.netbird.example.com \
#     bash

set -euo pipefail

SIGNAL_IMAGE="${SIGNAL_IMAGE:-@@DOCKERHUB_NAMESPACE@@/netbird-signal:@@IMAGE_TAG@@}"
SIGNAL_PORT="${NETBIRD_SIGNAL_PORT:-443}"

log() {
  printf '\n%s\n' "$*"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

check_dependencies() {
  command -v docker >/dev/null 2>&1 || die "Docker is required."
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

# read_value ENV_NAME PROMPT [DEFAULT]
read_value() {
  local env_name="$1" prompt="$2" default="${3:-}"
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

  if [[ -n "$default" ]]; then
    printf '%s' "$default"
    return
  fi

  die "$env_name is required in non-interactive mode."
}

validate_domain() {
  local domain="$1"

  [[ -n "$domain" ]] || die "Signal domain cannot be empty."
  [[ "$domain" != *"://"* ]] ||
    die "Signal domain must be a hostname only, for example signal.netbird.example.com."
  [[ "$domain" != */* && "$domain" != *:* ]] || die "Signal domain must not contain a path or port."
  [[ ${#domain} -le 253 ]] || die "Signal domain is too long."
  [[ "$domain" == *.* ]] ||
    die "Signal domain must be a fully-qualified domain name, for example signal.netbird.example.com."
  [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] ||
    die "Invalid signal domain: $domain"

  # Let's Encrypt requires the domain to resolve publicly to this server.
  if command -v getent >/dev/null 2>&1; then
    getent ahosts "$domain" >/dev/null 2>&1 || die "Signal domain does not resolve in DNS: $domain"
  elif command -v dig >/dev/null 2>&1; then
    [[ -n "$(dig +short "$domain" A "$domain" AAAA 2>/dev/null)" ]] ||
      die "Signal domain does not resolve in DNS: $domain"
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$domain" >/dev/null 2>&1 || die "Signal domain does not resolve in DNS: $domain"
  else
    echo "WARNING: getent, dig, and nslookup are unavailable; skipping DNS validation." >&2
  fi
}

configure() {
  [[ "$SIGNAL_PORT" =~ ^[0-9]+$ ]] && ((SIGNAL_PORT >= 1 && SIGNAL_PORT <= 65535)) ||
    die "NETBIRD_SIGNAL_PORT must be a port number."

  SIGNAL_DOMAIN="$(read_value NETBIRD_SIGNAL_DOMAIN "Signal domain (for example signal.netbird.example.com)")"
  validate_domain "$SIGNAL_DOMAIN"
}

check_existing() {
  if [[ -e docker-compose.yml || -e docker-compose.yaml || -e .env ]]; then
    echo "Signal configuration files already exist in the current directory." >&2
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

  # Signal answers the Let's Encrypt TLS challenge on port 443. When it serves
  # on another port, 443 must still be published for the challenge listener.
  local challenge_port=""
  if [[ "$SIGNAL_PORT" != "443" ]]; then
    challenge_port="
      - '443:443'"
  fi

  cat > docker-compose.yml <<EOF
services:
  signal:
    image: ${SIGNAL_IMAGE}
    container_name: netbird-signal
    restart: unless-stopped
    ports:
      - '${SIGNAL_PORT}:${SIGNAL_PORT}'${challenge_port}
    env_file:
      - .env
    volumes:
      - signal:/var/lib/netbird
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

volumes:
  signal:
    name: netbird-signal
    driver: local
EOF

  (
    umask 077
    cat > .env <<EOF
# NetBird Signal

NB_PORT=${SIGNAL_PORT}
NB_LOG_LEVEL=info
NB_LETSENCRYPT_DOMAIN=${SIGNAL_DOMAIN}
NB_LETSENCRYPT_DATA_DIR=/var/lib/netbird
EOF
  )
}

wait_for_container() {
  log "Waiting for the Signal container to start..."

  local retries=0 running
  while true; do
    running="$(docker inspect netbird-signal --format '{{.State.Running}}' 2>/dev/null || true)"
    if [[ "$running" == "true" ]]; then
      echo "Signal container is running."
      return 0
    fi

    retries=$((retries + 1))
    if [[ "$retries" -ge 30 ]]; then
      echo "" >&2
      echo "Signal failed to start. Recent logs:" >&2
      docker logs --tail=50 netbird-signal 2>&1 || true
      die "Signal did not start successfully."
    fi
    sleep 2
  done
}

verify_tls_certificate() {
  local retries=0 max_retries=30

  # A successful request means the certificate was issued and is trusted. HTTP
  # error statuses do not matter here (no --fail).
  while ! curl --silent --show-error --output /dev/null --connect-timeout 5 --max-time 10 \
    "https://${SIGNAL_DOMAIN}:${SIGNAL_PORT}/"; do
    retries=$((retries + 1))
    if [[ "$retries" -ge "$max_retries" ]]; then
      echo "" >&2
      echo "Unable to verify TLS for https://${SIGNAL_DOMAIN}:${SIGNAL_PORT}/" >&2
      echo "" >&2
      echo "Recent Signal logs:" >&2
      docker logs --tail=50 netbird-signal 2>&1 || true
      echo "" >&2
      die "Let's Encrypt certificate provisioning or TLS verification failed."
    fi
    echo "Waiting for certificate provisioning... (${retries}/${max_retries})"
    sleep 2
  done
  echo "TLS certificate is valid and trusted."
}

start_signal() {
  log "Starting NetBird Signal..."
  $DOCKER_COMPOSE up -d
  wait_for_container
  verify_tls_certificate
}

show_results() {
  local ports="${SIGNAL_PORT}/tcp"
  [[ "$SIGNAL_PORT" != "443" ]] && ports="${SIGNAL_PORT}/tcp and 443/tcp (certificate renewal)"

  cat <<EOF

==========================================
NetBird Signal installation complete
==========================================

Signal address: https://${SIGNAL_DOMAIN}:${SIGNAL_PORT}

Open ports: ${ports}

Use it from the NetBird server: add to the server section of its config.yaml
(this replaces the server's built-in Signal), then restart the server:

  signalUri: "https://${SIGNAL_DOMAIN}:${SIGNAL_PORT}"

Browser client / browser SSH: add the Signal WebSocket origin to NETBIRD_CSP
in the dashboard environment (space-separated with any existing entries),
then restart the dashboard:

  NETBIRD_CSP=wss://${SIGNAL_DOMAIN}

==========================================
EOF
}

main() {
  check_dependencies
  check_existing
  configure
  render_files
  start_signal
  show_results
}

main "$@"
