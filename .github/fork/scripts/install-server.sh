#!/usr/bin/env bash
#
# Installs a self-hosted NetBird server with Docker Compose: the combined
# NetBird server (management, signal, relay, STUN, embedded identity provider)
# and the dashboard behind Caddy, which obtains Let's Encrypt certificates.
#
# Optional, asked during install (or set with the variables below):
#   PostgreSQL     database for the server instead of SQLite
#   Reverse proxy  publishes services on *.<domain>; needs a wildcard DNS record
#   CrowdSec       blocks malicious IPs at Caddy and the reverse proxy, and can
#                  restrict the dashboard to (or block) countries
#
# Interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-server.sh | bash
#
# Non-interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-server.sh | \
#     NETBIRD_DOMAIN=netbird.example.com \
#     NETBIRD_LETSENCRYPT_EMAIL=admin@example.com \
#     NETBIRD_ENABLE_POSTGRES=true \
#     NETBIRD_ENABLE_PROXY=true \
#     NETBIRD_ENABLE_CROWDSEC=true \
#     NETBIRD_ALLOWED_COUNTRIES=US,CA \
#     bash
#
# Browser client: the dashboard's browser SSH and RDP run the NetBird client
# as WebAssembly. The installer downloads this release's build and Caddy
# serves it at https://<domain>/wasm/, so the browser client matches the
# server. Set NETBIRD_WASM_PATH to a URL to load it from elsewhere instead.
#
# Country filtering: NETBIRD_ALLOWED_COUNTRIES (only these may open the
# dashboard) or NETBIRD_BLOCKED_COUNTRIES (these may not), as comma-separated
# ISO 3166 codes. It applies to the dashboard only; peers, the API, Signal and
# relays stay reachable from everywhere.

set -euo pipefail

IMAGE_TAG="@@IMAGE_TAG@@"
NAMESPACE="@@DOCKERHUB_NAMESPACE@@"
RELEASE_URL="https://github.com/@@GITHUB_OWNER@@/netbird/releases/download/v${IMAGE_TAG}"
SERVER_IMAGE="${SERVER_IMAGE:-${NAMESPACE}/netbird-server:${IMAGE_TAG}}"
PROXY_IMAGE="${PROXY_IMAGE:-${NAMESPACE}/netbird-reverse-proxy:${IMAGE_TAG}}"
CADDY_IMAGE="${CADDY_IMAGE:-${NAMESPACE}/netbird-caddy:${IMAGE_TAG}}"
CROWDSEC_IMAGE="${CROWDSEC_IMAGE:-${NAMESPACE}/netbird-crowdsec:${IMAGE_TAG}}"
# The dashboard is released separately, so it follows its own latest release.
DASHBOARD_IMAGE="${DASHBOARD_IMAGE:-${NAMESPACE}/netbird-dashboard:latest}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:18}"

STUN_PORT="${NETBIRD_STUN_PORT:-3478}"
# Docker network for the stack. Caddy gets a fixed address so the server and
# the reverse proxy can trust client IPs forwarded by Caddy, and only by Caddy.
DOCKER_SUBNET="${NETBIRD_DOCKER_SUBNET:-172.30.0.0/24}"

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
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required."
  command -v gzip >/dev/null 2>&1 || die "gzip is required."

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

# read_yes_no ENV_NAME PROMPT DEFAULT(true|false) -> prints true or false
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

  [[ -n "$domain" ]] || die "Domain cannot be empty."
  [[ "$domain" != *"://"* ]] || die "Domain must be a hostname only, for example netbird.example.com."
  [[ "$domain" != */* && "$domain" != *:* ]] || die "Domain must not contain a path or port."
  [[ ${#domain} -le 253 ]] || die "Domain is too long."
  [[ "$domain" == *.* ]] || die "Domain must be a fully-qualified domain name, for example netbird.example.com."
  [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] ||
    die "Invalid domain: $domain"
  # Let's Encrypt requires the domain to resolve publicly to this server.
  resolves "$domain" || die "Domain does not resolve in DNS: $domain"
}

# normalize_countries "us, ca" -> "US CA"; dies on anything but 2-letter codes
normalize_countries() {
  local raw="${1^^}" code out=()
  raw="${raw//,/ }"
  for code in $raw; do
    [[ "$code" =~ ^[A-Z]{2}$ ]] || die "Invalid country code: $code (use ISO 3166 codes such as US, DE)"
    out+=("$code")
  done
  printf '%s' "${out[*]}"
}

configure() {
  DOMAIN="$(read_value NETBIRD_DOMAIN "NetBird domain (for example netbird.example.com)")"
  validate_domain "$DOMAIN"

  ACME_EMAIL="$(read_value NETBIRD_LETSENCRYPT_EMAIL \
    "Let's Encrypt email for certificate notices (leave empty for none)" "" optional)"
  if [[ -n "$ACME_EMAIL" && "$ACME_EMAIL" != *@*.* ]]; then
    die "Invalid email address: $ACME_EMAIL"
  fi

  ENABLE_POSTGRES="$(read_yes_no NETBIRD_ENABLE_POSTGRES "Use PostgreSQL instead of SQLite?" true)"
  ENABLE_PROXY="$(read_yes_no NETBIRD_ENABLE_PROXY \
    "Enable the reverse proxy, publishing services on *.${DOMAIN}?" true)"
  if [[ "$ENABLE_PROXY" == "true" ]] && ! resolves "nb-wildcard-check.${DOMAIN}"; then
    die "The reverse proxy needs a wildcard DNS record: *.${DOMAIN} must point to this server."
  fi
  ENABLE_CROWDSEC="$(read_yes_no NETBIRD_ENABLE_CROWDSEC "Enable CrowdSec protection?" true)"

  ALLOWED_COUNTRIES=""
  BLOCKED_COUNTRIES=""
  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    ALLOWED_COUNTRIES="$(normalize_countries "$(read_value NETBIRD_ALLOWED_COUNTRIES \
      "Only allow the dashboard from these countries, e.g. US,CA (leave empty for all)" "" optional)")"
    if [[ -z "$ALLOWED_COUNTRIES" ]]; then
      BLOCKED_COUNTRIES="$(normalize_countries "$(read_value NETBIRD_BLOCKED_COUNTRIES \
        "Block the dashboard from these countries, e.g. CN,RU (leave empty for none)" "" optional)")"
    elif [[ -n "${NETBIRD_BLOCKED_COUNTRIES:-}" ]]; then
      die "Set NETBIRD_ALLOWED_COUNTRIES or NETBIRD_BLOCKED_COUNTRIES, not both."
    fi
  elif [[ -n "${NETBIRD_ALLOWED_COUNTRIES:-}${NETBIRD_BLOCKED_COUNTRIES:-}" ]]; then
    die "Country filtering requires CrowdSec (NETBIRD_ENABLE_CROWDSEC=true)."
  fi

  [[ "$DOCKER_SUBNET" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.0/24$ ]] ||
    die "NETBIRD_DOCKER_SUBNET must be a /24 network such as 172.30.0.0/24."
  CADDY_IP="${BASH_REMATCH[1]}.10"

  # Secrets for this installation.
  AUTH_SECRET="$(openssl rand -base64 32 | tr -d '=')"
  STORE_ENCRYPTION_KEY="$(openssl rand -base64 32)"
  SESSION_COOKIE_KEY="$(openssl rand -base64 32)"
  POSTGRES_PASSWORD="$(openssl rand -hex 24)"
}

check_existing() {
  local f found=()
  for f in docker-compose.yml docker-compose.yaml config.yaml Caddyfile dashboard.env proxy.env \
    caddy.env postgres.env country-policy.yaml wasm; do
    [[ -e "$f" ]] && found+=("$f")
  done
  if [[ ${#found[@]} -gt 0 ]]; then
    echo "NetBird configuration files already exist in the current directory:" >&2
    printf '  %s\n' "${found[@]}" >&2
    echo "" >&2
    echo "Move or remove them, or run this installer in an empty directory." >&2
    exit 1
  fi
}

# Downloads this release's WebAssembly client into ./wasm and checks it against
# the release's checksums. Sets WASM_FILE (served by Caddy) and WASM_URL (given
# to the dashboard); both stay empty if the dashboard should use its default.
download_wasm() {
  WASM_FILE=""
  WASM_URL="${NETBIRD_WASM_PATH:-}"
  if [[ -n "$WASM_URL" ]]; then
    log "Browser client: using ${WASM_URL}"
    return
  fi

  local name="netbird_${IMAGE_TAG}.wasm" sums expected actual
  log "Downloading the browser client (${name})..."
  mkdir -p wasm
  chmod 755 wasm
  if ! curl -fsSL --retry 3 -o "wasm/${name}.part" "${RELEASE_URL}/${name}" ||
    ! sums="$(curl -fsSL --retry 3 "${RELEASE_URL}/netbird_${IMAGE_TAG}_checksums.txt")"; then
    rm -f "wasm/${name}.part"
    rmdir wasm
    echo "WARNING: could not download the browser client; the dashboard will use its built-in default." >&2
    return
  fi
  expected="$(awk -v f="$name" '$2 == f { print $1 }' <<<"$sums")"
  actual="$(sha256sum "wasm/${name}.part" | awk '{ print $1 }')"
  if [[ -z "$expected" || "$expected" != "$actual" ]]; then
    rm -f "wasm/${name}.part"
    die "The browser client ${name} does not match the release's checksum."
  fi
  mv "wasm/${name}.part" "wasm/${name}"
  # Served precompressed: about a quarter of the size, without Caddy
  # compressing 60 MB on every download.
  gzip -kf "wasm/${name}"
  chmod 644 "wasm/${name}" "wasm/${name}.gz"
  WASM_FILE="$name"
  WASM_URL="https://${DOMAIN}/wasm/${name}"
}

render_config_yaml() {
  local store
  if [[ "$ENABLE_POSTGRES" == "true" ]]; then
    local dsn="host=postgres user=netbird password=${POSTGRES_PASSWORD} dbname=netbird port=5432 sslmode=disable"
    store="  store:
    engine: \"postgres\"
    dsn: \"${dsn}\"
    encryptionKey: \"${STORE_ENCRYPTION_KEY}\"
  activityStore:
    engine: \"postgres\"
    dsn: \"${dsn}\"
  authStore:
    engine: \"postgres\"
    dsn: \"${dsn}\""
  else
    store="  store:
    engine: \"sqlite\"
    encryptionKey: \"${STORE_ENCRYPTION_KEY}\""
  fi

  cat <<EOF
# NetBird server configuration (generated by install-server.sh)

server:
  listenAddress: ":80"
  exposedAddress: "https://${DOMAIN}:443"
  stunPorts:
    - ${STUN_PORT}
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"
  dataDir: "/var/lib/netbird"

  # Relay authentication secret. External relays must use the same secret.
  authSecret: "${AUTH_SECRET}"

  auth:
    issuer: "https://${DOMAIN}/oauth2"
    signKeyRefreshEnabled: true
    sessionCookieEncryptionKey: "${SESSION_COOKIE_KEY}"
    dashboardRedirectURIs:
      - "https://${DOMAIN}/nb-auth"
      - "https://${DOMAIN}/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"

  reverseProxy:
    # Only Caddy may forward client IPs.
    trustedHTTPProxies:
      - "${CADDY_IP}/32"

  # Keep the encryption key safe: without it the stored data cannot be read.
${store}
EOF
}

render_dashboard_env() {
  cat <<EOF
# NetBird dashboard
NETBIRD_MGMT_API_ENDPOINT=https://${DOMAIN}
NETBIRD_MGMT_GRPC_API_ENDPOINT=https://${DOMAIN}
# Embedded identity provider
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_CLIENT_SECRET=
AUTH_AUTHORITY=https://${DOMAIN}/oauth2
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES=openid profile email groups
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
# TLS is terminated by Caddy
NGINX_SSL_PORT=443
LETSENCRYPT_DOMAIN=none
EOF
  if [[ -n "$WASM_URL" ]]; then
    cat <<EOF
# Browser client (WebAssembly) for browser SSH and RDP
NETBIRD_WASM_PATH=${WASM_URL}
EOF
  fi
}

render_proxy_env() {
  cat <<EOF
# NetBird reverse proxy
NB_PROXY_LOG_LEVEL=info
# Reach management over the internal Docker network
NB_PROXY_MANAGEMENT_ADDRESS=http://server:80
NB_PROXY_ALLOW_INSECURE=true
NB_PROXY_DOMAIN=${DOMAIN}
NB_PROXY_ADDRESS=:8443
NB_PROXY_TOKEN=${PROXY_TOKEN}
NB_PROXY_CERTIFICATE_DIRECTORY=/certs
NB_PROXY_ACME_CERTIFICATES=true
NB_PROXY_ACME_CHALLENGE_TYPE=tls-alpn-01
NB_PROXY_FORWARDED_PROTO=https
# Caddy passes connections through with the PROXY protocol; trust only Caddy.
NB_PROXY_PROXY_PROTOCOL=true
NB_PROXY_TRUSTED_PROXIES=${CADDY_IP}
EOF
  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    cat <<EOF
NB_PROXY_CROWDSEC_API_URL=http://crowdsec:8080
NB_PROXY_CROWDSEC_API_KEY=${PROXY_CROWDSEC_KEY}
EOF
  fi
}

render_caddyfile() {
  local global_extra="" site_log="" site_crowdsec="" dashboard_appsec="" listener_wrappers=""
  local wasm_routes=""

  if [[ -n "$WASM_FILE" ]]; then
    wasm_routes="
	# Browser client (WebAssembly) from this release. Its file name holds the
	# version, so browsers may cache it for good.
	handle /wasm/* {
		root * /srv
		header Cache-Control \"public, max-age=31536000, immutable\"
		file_server {
			precompressed gzip
		}
	}
"
  fi

  [[ -n "$ACME_EMAIL" ]] && global_extra+="
	email ${ACME_EMAIL}"

  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    global_extra+="
	crowdsec {
		api_url http://crowdsec:8080
		api_key {\$CADDY_CROWDSEC_API_KEY}
		ticker_interval 15s
		appsec_url http://crowdsec:7422
	}
	# Access log read by CrowdSec
	log {
		output file /var/log/caddy/access.log {
			roll_size 50MiB
			roll_keep 5
		}
		format json
	}"
    site_log="
	log"
    site_crowdsec="
		crowdsec"
    # Country filtering and AppSec rules apply to the dashboard only.
    dashboard_appsec="
			appsec"
  fi

  if [[ "$ENABLE_PROXY" == "true" ]]; then
    listener_wrappers="
		# Services published by the reverse proxy: pass TLS through untouched.
		listener_wrappers {
			layer4 {
				@passthrough tls sni *.${DOMAIN}
				route @passthrough {
					proxy proxy:8443 {
						proxy_protocol v2
					}
				}
			}
			tls
		}"
  fi

  cat <<EOF
# Caddy configuration for NetBird (generated by install-server.sh)
{
	admin off${global_extra}
	servers {${listener_wrappers}
		protocols h1 h2c h2 h3
		# gRPC and relay connections are long-lived streams.
		timeouts {
			read_body 0
			read_header 0
			write 0
			idle 0
		}
	}
}

(security_headers) {
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "strict-origin-when-cross-origin"
		Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
		Cross-Origin-Opener-Policy "same-origin"
		Cross-Origin-Resource-Policy "same-origin"
		-Server
		-X-Powered-By
		-Via
		defer
	}
}

(ratelimit) {
	rate_limit {
		zone dynamic {
			key {remote_host}
			events 1000
			window 1m
		}
	}
}

(netbird_routes) {
	# gRPC: Signal, management and the reverse proxy's management connection
	@grpc header Content-Type application/grpc*
	handle @grpc {
		reverse_proxy h2c://server:80 {
			flush_interval -1
		}
	}

	# Relay, WebSocket proxy, API and the embedded identity provider
	@backend path /relay* /ws-proxy/* /api/* /oauth2/* /federation/*
	handle @backend {
		reverse_proxy server:80 {
			flush_interval -1
		}
	}

${wasm_routes}	# Dashboard. handle sorts its directives again; the inner route keeps
	# appsec first.
	handle {
		route {${dashboard_appsec}
			import security_headers
			import ratelimit
			reverse_proxy dashboard:80
		}
	}
}

${DOMAIN} {
	encode zstd gzip${site_log}
	# route keeps the handlers in this order; plugin handlers such as
	# rate_limit and appsec have no default position outside it.
	route {${site_crowdsec}
		import netbird_routes
	}
}
EOF
}

render_country_policy() {
  local list="" code
  for code in ${ALLOWED_COUNTRIES:-$BLOCKED_COUNTRIES}; do
    list+="${list:+, }\"${code}\""
  done

  # Private addresses (Docker networks, LAN) are never filtered.
  local private='IpInRange(req.RemoteAddr, "10.0.0.0/8") || IpInRange(req.RemoteAddr, "172.16.0.0/12") || IpInRange(req.RemoteAddr, "192.168.0.0/16") || IpInRange(req.RemoteAddr, "127.0.0.0/8")'

  echo "# Country filter for the NetBird dashboard (generated by install-server.sh)"
  echo "name: netbird/country-policy"
  if [[ -n "$ALLOWED_COUNTRIES" ]]; then
    cat <<EOF
# Only these countries may open the dashboard.
pre_eval:
  - filter: IsInBand == true && !(${private}) && GeoIPEnrich(req.RemoteAddr)?.Country.IsoCode not in [${list}]
    apply:
      - DropRequest("Country not allowed")
EOF
  elif [[ -n "$BLOCKED_COUNTRIES" ]]; then
    cat <<EOF
# These countries may not open the dashboard.
pre_eval:
  - filter: IsInBand == true && !(${private}) && GeoIPEnrich(req.RemoteAddr)?.Country.IsoCode in [${list}]
    apply:
      - DropRequest("Country blocked")
EOF
  else
    echo "# No country filtering. Rerun the installer or edit this file to add it."
  fi
}

render_compose() {
  local postgres_service="" postgres_depends="" crowdsec_service="" proxy_service="" volumes=""
  local caddy_wasm=""

  [[ -n "$WASM_FILE" ]] && caddy_wasm="
      - ./wasm:/srv/wasm:ro"

  if [[ "$ENABLE_POSTGRES" == "true" ]]; then
    postgres_service="
  postgres:
    image: ${POSTGRES_IMAGE}
    container_name: netbird-postgres
    <<: *default
    env_file:
      - ./postgres.env
    healthcheck:
      test: [\"CMD-SHELL\", \"pg_isready -U \$\$POSTGRES_USER -d \$\$POSTGRES_DB\"]
      interval: 5s
      timeout: 5s
      retries: 10
    volumes:
      - netbird-postgres:/var/lib/postgresql
"
    postgres_depends="
    depends_on:
      postgres:
        condition: service_healthy"
    volumes+="
  netbird-postgres:
    name: netbird-postgres"
  fi

  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    crowdsec_service="
  crowdsec:
    image: ${CROWDSEC_IMAGE}
    container_name: netbird-crowdsec
    <<: *default
    healthcheck:
      test: [\"CMD\", \"cscli\", \"lapi\", \"status\"]
      interval: 5s
      timeout: 5s
      retries: 20
      start_period: 30s
    volumes:
      - netbird-crowdsec:/etc/crowdsec
      - netbird-crowdsec-data:/var/lib/crowdsec/data
      - netbird-caddy-log:/var/log/caddy:ro
      - ./country-policy.yaml:/etc/crowdsec/appsec-configs/country-policy.yaml:ro
"
    volumes+="
  netbird-crowdsec:
    name: netbird-crowdsec
  netbird-crowdsec-data:
    name: netbird-crowdsec-data"
  fi

  if [[ "$ENABLE_PROXY" == "true" ]]; then
    proxy_service="
  proxy:
    image: ${PROXY_IMAGE}
    container_name: netbird-proxy
    <<: *default
    ports:
      - '51820:51820/udp'
    env_file:
      - ./proxy.env
    volumes:
      - netbird-proxy:/certs
    depends_on:
      server:
        condition: service_healthy
"
    volumes+="
  netbird-proxy:
    name: netbird-proxy"
  fi

  cat <<EOF
# NetBird server stack (generated by install-server.sh)

x-default: &default
  restart: unless-stopped
  networks:
    - netbird
  logging:
    driver: "json-file"
    options:
      max-size: "50m"
      max-file: "5"

services:
${postgres_service}
  server:
    image: ${SERVER_IMAGE}
    container_name: netbird-server
    <<: *default
    command: ["--config", "/etc/netbird/config.yaml"]
    ports:
      - '${STUN_PORT}:${STUN_PORT}/udp'
    healthcheck:
      test: ["CMD-SHELL", "bash -c 'cat /dev/null > /dev/tcp/localhost/9000' || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s
    volumes:
      - netbird-server:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml:ro${postgres_depends}

  dashboard:
    image: ${DASHBOARD_IMAGE}
    container_name: netbird-dashboard
    <<: *default
    env_file:
      - ./dashboard.env
${crowdsec_service}${proxy_service}
  caddy:
    image: ${CADDY_IMAGE}
    container_name: netbird-caddy
    restart: unless-stopped
    networks:
      netbird:
        ipv4_address: ${CADDY_IP}
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"
    env_file:
      - ./caddy.env
    ports:
      - '80:80'
      - '443:443'
      - '443:443/udp'
    volumes:
      - netbird-caddy:/data
      - netbird-caddy-log:/var/log/caddy
      - ./Caddyfile:/etc/caddy/Caddyfile:ro${caddy_wasm}
    depends_on:
      server:
        condition: service_healthy
      dashboard:
        condition: service_started

volumes:
  netbird-server:
    name: netbird-server
  netbird-caddy:
    name: netbird-caddy
  netbird-caddy-log:
    name: netbird-caddy-log${volumes}

networks:
  netbird:
    name: netbird
    ipam:
      config:
        - subnet: ${DOCKER_SUBNET}
EOF
}

render_files() {
  log "Generating configuration files..."
  umask 077

  render_config_yaml > config.yaml
  render_dashboard_env > dashboard.env
  render_caddyfile > Caddyfile
  render_compose > docker-compose.yml
  : > caddy.env

  if [[ "$ENABLE_POSTGRES" == "true" ]]; then
    cat > postgres.env <<EOF
POSTGRES_DB=netbird
POSTGRES_USER=netbird
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
EOF
  fi
  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    render_country_policy > country-policy.yaml
    chmod 644 country-policy.yaml
  fi
  # Bind-mounted into containers or harmless; config.yaml and the .env files
  # hold secrets and stay readable by the owner only (the server runs as root,
  # and Compose reads the .env files on the host).
  chmod 644 Caddyfile docker-compose.yml
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

container_healthy() {
  [[ "$(docker inspect "$1" --format '{{.State.Health.Status}}' 2>/dev/null)" == "healthy" ]]
}

show_logs_and_die() {
  local container
  for container in "$@"; do
    echo "" >&2
    echo "Recent logs of ${container}:" >&2
    docker logs --tail=40 "$container" 2>&1 || true
  done
  die "Installation did not complete. The files are in $(pwd); fix the problem and run: $DOCKER_COMPOSE up -d"
}

start_crowdsec() {
  log "Starting CrowdSec..."
  $DOCKER_COMPOSE up -d crowdsec
  wait_until "CrowdSec" 90 $DOCKER_COMPOSE exec -T crowdsec cscli lapi status ||
    show_logs_and_die netbird-crowdsec

  log "Creating CrowdSec bouncer keys..."
  CADDY_CROWDSEC_KEY="$($DOCKER_COMPOSE exec -T crowdsec cscli bouncers add caddy -o raw | tr -d '\r\n')"
  PROXY_CROWDSEC_KEY="$($DOCKER_COMPOSE exec -T crowdsec cscli bouncers add netbird-proxy -o raw | tr -d '\r\n')"
  [[ -n "$CADDY_CROWDSEC_KEY" && -n "$PROXY_CROWDSEC_KEY" ]] || show_logs_and_die netbird-crowdsec
  echo "CADDY_CROWDSEC_API_KEY=${CADDY_CROWDSEC_KEY}" > caddy.env
}

start_core() {
  log "Starting the NetBird server, dashboard and Caddy..."
  local services=(server dashboard caddy)
  [[ "$ENABLE_POSTGRES" == "true" ]] && services=(postgres "${services[@]}")
  $DOCKER_COMPOSE up -d "${services[@]}"

  wait_until "the NetBird server" 90 container_healthy netbird-server ||
    show_logs_and_die netbird-server
  echo "NetBird server is running."

  log "Waiting for the Let's Encrypt certificate for ${DOMAIN}..."
  wait_until "https://${DOMAIN}" 60 curl --silent --output /dev/null --connect-timeout 5 --max-time 10 \
    "https://${DOMAIN}/" || show_logs_and_die netbird-caddy
  echo "TLS certificate is valid and trusted."
}

start_proxy() {
  log "Creating the reverse proxy access token..."
  PROXY_TOKEN="$($DOCKER_COMPOSE exec -T server /go/bin/netbird-server admin token create \
    --name default-proxy --config /etc/netbird/config.yaml 2>/dev/null | awk '/^Token:/ {print $2}')"
  [[ -n "$PROXY_TOKEN" ]] || show_logs_and_die netbird-server

  render_proxy_env > proxy.env
  log "Starting the reverse proxy..."
  $DOCKER_COMPOSE up -d proxy
  sleep 5
  [[ "$(docker inspect netbird-proxy --format '{{.State.Running}}' 2>/dev/null)" == "true" ]] ||
    show_logs_and_die netbird-proxy
}

show_results() {
  local browser_client="${WASM_URL:-the default built into the dashboard}"
  cat <<EOF

==========================================
NetBird server installation complete
==========================================

Dashboard: https://${DOMAIN}
Open it and follow the onboarding steps to create the first (owner) account.

Open ports:
  80/tcp, 443/tcp, 443/udp   Caddy (HTTPS, HTTP/3, certificate issuance)
  ${STUN_PORT}/udp                   STUN
EOF
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    cat <<EOF
  51820/udp                  reverse proxy (optional, direct peer connections)

Reverse proxy: services are published on *.${DOMAIN}. To serve another domain,
add its name to the @passthrough line in the Caddyfile and restart Caddy.
EOF
  fi
  if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
    local countries="no country filtering"
    [[ -n "$ALLOWED_COUNTRIES" ]] && countries="only from ${ALLOWED_COUNTRIES// /, }"
    [[ -n "$BLOCKED_COUNTRIES" ]] && countries="blocked from ${BLOCKED_COUNTRIES// /, }"
    cat <<EOF

CrowdSec: active at Caddy$([[ "$ENABLE_PROXY" == "true" ]] && echo " and the reverse proxy"). Dashboard access: ${countries}
(edit country-policy.yaml, then: $DOCKER_COMPOSE restart crowdsec).
EOF
  fi
  cat <<EOF

Browser client: ${browser_client}

Files are in $(pwd). Back up config.yaml$([[ "$ENABLE_POSTGRES" == "true" ]] && echo " and postgres.env"): config.yaml holds
the store encryption key, without which the stored data cannot be read.

To add standalone relays or Signal servers, use install-relay.sh and
install-signal.sh from the same release; this server's relay secret is the
authSecret in config.yaml.

==========================================
EOF
}

main() {
  check_dependencies
  check_existing
  configure
  download_wasm
  render_files
  [[ "$ENABLE_CROWDSEC" == "true" ]] && start_crowdsec
  start_core
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    PROXY_CROWDSEC_KEY="${PROXY_CROWDSEC_KEY:-}"
    start_proxy
  fi
  show_results
}

main "$@"
