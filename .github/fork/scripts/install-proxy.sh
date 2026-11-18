#!/usr/bin/env bash
#
# Installs a standalone NetBird reverse proxy using Docker Compose, on its own
# host. It connects to an existing NetBird server and publishes services on
# *.<proxy domain>, with Let's Encrypt certificates obtained by the proxy itself.
#
# Interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-proxy.sh | bash
#
# Non-interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-proxy.sh | \
#     NETBIRD_PROXY_DOMAIN=proxy.netbird.example.com \
#     NETBIRD_MANAGEMENT_URL=https://netbird.example.com \
#     NETBIRD_PROXY_TOKEN='token from the NetBird server' \
#     bash
#
# The token is created on the NetBird server host, in the directory of its
# docker-compose.yml:
#
#   docker compose exec -T server /go/bin/netbird-server admin token create \
#     --name proxy1 --config /etc/netbird/config.yaml
#
# Optional: NETBIRD_PROXY_PRIVATE (default true) serves NetBird-Only services to
# NetBird peers inside the WireGuard tunnel.
#
# Optional: NETBIRD_ENABLE_CROWDSEC (default true) runs CrowdSec next to the
# proxy for IP reputation checks (the CrowdSec community blocklist). Turn it on
# per service in the dashboard (service access control, CrowdSec IP Reputation).
#
# DNS: <proxy domain> and *.<proxy domain> must point to this host.

set -euo pipefail

PROXY_IMAGE="${PROXY_IMAGE:-@@DOCKERHUB_NAMESPACE@@/netbird-reverse-proxy:@@IMAGE_TAG@@}"
CROWDSEC_IMAGE="${CROWDSEC_IMAGE:-crowdsecurity/crowdsec:v1.8.2}"
# The image runs as a non-root user and listens on 8443 inside the container.
CONTAINER_PORT=8443

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

# read_yes_no ENV_NAME PROMPT DEFAULT -> prints true or false
read_yes_no() {
  local env_name="$1" prompt="$2" default="$3" value hint="y/N"
  [[ "$default" == "true" ]] && hint="Y/n"
  value="$(read_value "$env_name" "$prompt ($hint)" "" optional)"
  case "${value,,}" in
    "") printf '%s' "$default" ;;
    y | yes | true | 1) printf 'true' ;;
    n | no | false | 0) printf 'false' ;;
    *) die "$env_name must be yes or no, got: $value" ;;
  esac
}

resolves() {
  local name="$1"
  if command -v getent >/dev/null 2>&1; then
    getent ahosts "$name" >/dev/null 2>&1
  elif command -v dig >/dev/null 2>&1; then
    [[ -n "$(dig +short "$name" A "$name" AAAA 2>/dev/null)" ]]
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$name" >/dev/null 2>&1
  else
    echo "WARNING: getent, dig, and nslookup are unavailable; skipping DNS validation." >&2
    return 0
  fi
}

validate_domain() {
  local domain="$1"

  [[ -n "$domain" ]] || die "Proxy domain cannot be empty."
  [[ "$domain" != *"://"* ]] ||
    die "Proxy domain must be a hostname only, for example proxy.netbird.example.com."
  [[ "$domain" != */* && "$domain" != *:* ]] || die "Proxy domain must not contain a path or port."
  [[ ${#domain} -le 253 ]] || die "Proxy domain is too long."
  [[ "$domain" == *.* ]] ||
    die "Proxy domain must be a fully-qualified domain name, for example proxy.netbird.example.com."
  [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] ||
    die "Invalid proxy domain: $domain"

  # Let's Encrypt needs every service name to resolve publicly to this host.
  resolves "$domain" || die "Proxy domain does not resolve in DNS: $domain"
  resolves "nb-wildcard-check.${domain}" ||
    die "The reverse proxy needs a wildcard DNS record: *.${domain} must point to this host."
}

configure() {
  PROXY_DOMAIN="$(read_value NETBIRD_PROXY_DOMAIN \
    "Proxy domain; services are published on *.<domain> (for example proxy.netbird.example.com)")"
  validate_domain "$PROXY_DOMAIN"

  MANAGEMENT_URL="$(read_value NETBIRD_MANAGEMENT_URL "NetBird server URL (for example https://netbird.example.com)")"
  MANAGEMENT_URL="${MANAGEMENT_URL%/}"
  [[ "$MANAGEMENT_URL" =~ ^https://[^/[:space:]]+$ ]] ||
    die "Server URL must look like https://netbird.example.com (https, no path)."
  # The proxy dials management over gRPC and needs an explicit port.
  MANAGEMENT_ADDRESS="$MANAGEMENT_URL"
  [[ "${MANAGEMENT_URL#https://}" == *:* ]] || MANAGEMENT_ADDRESS="${MANAGEMENT_URL}:443"

  if [[ -z "${NETBIRD_PROXY_TOKEN:-}" ]] && tty_available; then
    cat >/dev/tty <<'EOF'

Create a proxy token on the NetBird server host, in the directory of its
docker-compose.yml (use a different --name for each proxy):

  docker compose exec -T server /go/bin/netbird-server admin token create \
    --name proxy1 --config /etc/netbird/config.yaml

Paste the token from the "Token:" line (it starts with nbx_).

EOF
  fi
  PROXY_TOKEN="$(read_value NETBIRD_PROXY_TOKEN "Proxy token")"
  [[ -n "$PROXY_TOKEN" ]] || die "A proxy token is required."

  PROXY_PRIVATE="$(read_yes_no NETBIRD_PROXY_PRIVATE \
    "Serve NetBird-Only services to NetBird peers inside the tunnel?" true)"

  ENABLE_CROWDSEC="$(read_yes_no NETBIRD_ENABLE_CROWDSEC \
    "Add CrowdSec to block known-malicious IPs?" true)"
}

check_existing() {
  local f found=()
  for f in docker-compose.yml docker-compose.yaml proxy.env; do
    [[ -e "$f" ]] && found+=("$f")
  done
  if [[ ${#found[@]} -gt 0 ]]; then
    echo "Proxy configuration files already exist in the current directory:" >&2
    printf '  %s\n' "${found[@]}" >&2
    echo "" >&2
    echo "Move or remove them, or run this installer in an empty directory." >&2
    exit 1
  fi
}

render_files() {
  log "Generating configuration files..."

  local crowdsec_service="" crowdsec_volumes="" proxy_depends=""
  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    # No log is read on this host: CrowdSec serves the community blocklist (and
    # any decision added with cscli) to the proxy. The Linux collection gives it
    # the scenarios the blocklist is pulled for.
    crowdsec_service="
  crowdsec:
    image: ${CROWDSEC_IMAGE}
    container_name: netbird-proxy-crowdsec
    <<: *default
    environment:
      COLLECTIONS: crowdsecurity/linux
    healthcheck:
      test: [\"CMD\", \"cscli\", \"lapi\", \"status\"]
      interval: 5s
      timeout: 5s
      retries: 20
      start_period: 30s
    volumes:
      - crowdsec:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
"
    crowdsec_volumes="
  crowdsec:
    name: netbird-proxy-crowdsec
    driver: local
  crowdsec-data:
    name: netbird-proxy-crowdsec-data
    driver: local"
    proxy_depends="
    depends_on:
      crowdsec:
        condition: service_healthy"
  fi

  cat > docker-compose.yml <<EOF
# NetBird reverse proxy (generated by install-proxy.sh)

x-default: &default
  restart: unless-stopped
  networks:
    - netbird-proxy
  logging:
    driver: "json-file"
    options:
      max-size: "50m"
      max-file: "5"

services:${crowdsec_service}
  proxy:
    image: ${PROXY_IMAGE}
    container_name: netbird-proxy
    <<: *default
    ports:
      # HTTPS for published services and the Let's Encrypt TLS-ALPN challenge
      - '443:${CONTAINER_PORT}'
    env_file:
      - ./proxy.env
    volumes:
      - proxy:/certs${proxy_depends}

volumes:
  proxy:
    name: netbird-proxy
    driver: local${crowdsec_volumes}

networks:
  netbird-proxy:
    name: netbird-proxy
    driver: bridge
EOF

  (
    umask 077
    cat > proxy.env <<EOF
# NetBird reverse proxy

NB_PROXY_LOG_LEVEL=info
# NetBird server (management gRPC)
NB_PROXY_MANAGEMENT_ADDRESS=${MANAGEMENT_ADDRESS}
# Access token created with: netbird-server admin token create
NB_PROXY_TOKEN=${PROXY_TOKEN}
# Services are published on *.${PROXY_DOMAIN}
NB_PROXY_DOMAIN=${PROXY_DOMAIN}
NB_PROXY_ADDRESS=:${CONTAINER_PORT}
# Let's Encrypt, answered on port 443
NB_PROXY_CERTIFICATE_DIRECTORY=/certs
NB_PROXY_ACME_CERTIFICATES=true
NB_PROXY_ACME_CHALLENGE_TYPE=tls-alpn-01
NB_PROXY_FORWARDED_PROTO=https
# Private services (NetBird-Only authentication): reachable only from NetBird
# peers, on :80 and :443 inside each account's WireGuard tunnel. Public
# services are unaffected.
NB_PROXY_PRIVATE=${PROXY_PRIVATE}

# Optional: a fixed WireGuard port for direct peer connections (otherwise
# random, and traffic goes through relays). Single-account servers only.
# Publish it in docker-compose.yml as well: - '51820:51820/udp'
# NB_PROXY_WG_PORT=51820

EOF
    if [[ "$ENABLE_CROWDSEC" != "true" ]]; then
      cat >> proxy.env <<EOF

# Optional: CrowdSec bouncer
# NB_PROXY_CROWDSEC_API_URL=http://crowdsec.example.com:8080
# NB_PROXY_CROWDSEC_API_KEY=
EOF
    fi
  )
}

wait_until() {
  # wait_until DESCRIPTION TRIES COMMAND...
  local what="$1" tries="$2" i
  shift 2
  for ((i = 1; i <= tries; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 2
  done
  echo "Timed out waiting for ${what}." >&2
  return 1
}

start_crowdsec() {
  log "Starting CrowdSec..."
  $DOCKER_COMPOSE up -d crowdsec
  # shellcheck disable=SC2086 # DOCKER_COMPOSE is "docker compose", split on purpose
  if ! wait_until "CrowdSec" 90 $DOCKER_COMPOSE exec -T crowdsec cscli lapi status; then
    docker logs --tail=40 netbird-proxy-crowdsec 2>&1 || true
    die "CrowdSec did not start. The files are in $(pwd)."
  fi

  log "Creating the CrowdSec bouncer key for the proxy..."
  local key
  key="$($DOCKER_COMPOSE exec -T crowdsec cscli bouncers add netbird-proxy -o raw | tr -d '\r\n')"
  [[ -n "$key" ]] || die "Could not create the CrowdSec bouncer key."
  (
    umask 077
    cat >> proxy.env <<EOF

# CrowdSec (IP reputation). Enable it per service in the dashboard.
NB_PROXY_CROWDSEC_API_URL=http://crowdsec:8080
NB_PROXY_CROWDSEC_API_KEY=${key}
EOF
  )
}

wait_for_proxy() {
  log "Waiting for the proxy to connect to the NetBird server..."

  local retries=0 max_retries=60
  while true; do
    if docker logs netbird-proxy 2>&1 | grep -q "Initial mapping sync complete"; then
      echo "Proxy is connected to ${MANAGEMENT_URL}."
      return 0
    fi

    if [[ "$(docker inspect netbird-proxy --format '{{.State.Running}}' 2>/dev/null || true)" != "true" ]] &&
      [[ "$retries" -ge 5 ]]; then
      break
    fi

    retries=$((retries + 1))
    [[ "$retries" -lt "$max_retries" ]] || break
    sleep 2
  done

  echo "" >&2
  echo "The proxy did not connect to the NetBird server. Recent logs:" >&2
  docker logs --tail=50 netbird-proxy 2>&1 || true
  echo "" >&2
  die "Check the server URL and the proxy token."
}

start_proxy() {
  log "Starting the NetBird reverse proxy..."
  $DOCKER_COMPOSE up -d proxy
  wait_for_proxy
}

show_results() {
  cat <<EOF

==========================================
NetBird reverse proxy installation complete
==========================================

Proxy domain:  ${PROXY_DOMAIN} (services on *.${PROXY_DOMAIN})
NetBird server: ${MANAGEMENT_URL}

Open ports: 443/tcp
EOF
  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    cat <<EOF
CrowdSec:      running (community blocklist). Turn it on per service in the
               dashboard: service access control, CrowdSec IP Reputation
               (Enforce or Observe). Block an IP by hand:
               $DOCKER_COMPOSE exec crowdsec cscli decisions add --ip <ip>
EOF
  fi
  cat <<EOF

Create services in the dashboard (Reverse Proxy) and choose ${PROXY_DOMAIN}
as the domain. Each service's certificate is issued on its first request.

TCP/UDP services listen on their own ports; publish those ports in
docker-compose.yml and open them in the firewall.

==========================================
EOF
}

main() {
  check_dependencies
  check_existing
  configure
  render_files
  [[ "$ENABLE_CROWDSEC" == "true" ]] && start_crowdsec
  start_proxy
  show_results
}

main "$@"
