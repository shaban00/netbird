#!/usr/bin/env bash
#
# Installs the NetBird SSH session recorder using Docker Compose. The recorder
# is a NetBird peer: it joins your network with a setup key and is reachable
# only over the NetBird tunnel (gRPC on port 22023, web UI on port 8080).
#
# Interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-recorder.sh | bash
#
# Non-interactive:
#
#   curl -fsSL https://github.com/@@GITHUB_OWNER@@/netbird/releases/latest/download/install-recorder.sh | \
#     NETBIRD_MANAGEMENT_URL=https://netbird.example.com \
#     NETBIRD_SETUP_KEY=<setup key> \
#     bash
#
# Optional: NETBIRD_RECORDER_ENCRYPTION_KEY (reuse an existing key; otherwise one
# is generated), NETBIRD_RECORDER_DEVICE_NAME, NETBIRD_RECORDER_RETENTION_DAYS,
# and for a login in front of the web UI: NETBIRD_RECORDER_OIDC_ISSUER,
# NETBIRD_RECORDER_OIDC_CLIENT_ID, NETBIRD_RECORDER_OIDC_CLIENT_SECRET,
# NETBIRD_RECORDER_OIDC_ALLOWED_GROUPS.
#
# Database for the recording index (session list, users, times); the
# recordings themselves are files on the netbird-recorder volume either way:
#   SQLite (default)  a file on the netbird-recorder volume
#   PostgreSQL        NETBIRD_RECORDER_ENABLE_POSTGRES=true runs one in a
#                     container next to the recorder, or set
#                     NETBIRD_RECORDER_POSTGRES_DSN to use an existing database

set -euo pipefail

RECORDER_IMAGE="${RECORDER_IMAGE:-@@DOCKERHUB_NAMESPACE@@/netbird-recorder:@@IMAGE_TAG@@}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:18}"
GRPC_PORT=22023
HTTP_PORT=8080

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

configure() {
  MANAGEMENT_URL="$(read_value NETBIRD_MANAGEMENT_URL "NetBird management URL (for example https://netbird.example.com)")"
  MANAGEMENT_URL="${MANAGEMENT_URL%/}"
  [[ "$MANAGEMENT_URL" =~ ^https?://[^/[:space:]]+$ ]] ||
    die "Management URL must look like https://netbird.example.com (no path)."

  SETUP_KEY="$(read_value NETBIRD_SETUP_KEY "Setup key for the recorder (Dashboard > Setup Keys)")"
  [[ -n "$SETUP_KEY" ]] || die "A setup key is required."

  DEVICE_NAME="$(read_value NETBIRD_RECORDER_DEVICE_NAME "Device name" "netbird-recorder")"

  RETENTION_DAYS="$(read_value NETBIRD_RECORDER_RETENTION_DAYS "Delete recordings after how many days (0 keeps them forever)" "0")"
  [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || die "Retention must be a whole number of days."

  # Database for the recording index.
  POSTGRES_DSN="${NETBIRD_RECORDER_POSTGRES_DSN:-}"
  BUNDLED_POSTGRES=false
  if [[ -n "$POSTGRES_DSN" ]]; then
    STORE_ENGINE=postgres
  else
    BUNDLED_POSTGRES="$(read_yes_no NETBIRD_RECORDER_ENABLE_POSTGRES \
      "Use PostgreSQL instead of SQLite for the recording index?" false)"
    STORE_ENGINE=sqlite
    if [[ "$BUNDLED_POSTGRES" == "true" ]]; then
      STORE_ENGINE=postgres
      POSTGRES_PASSWORD="$(openssl rand -hex 24)"
      POSTGRES_DSN="host=postgres user=recorder password=${POSTGRES_PASSWORD} dbname=recorder port=5432 sslmode=disable"
    fi
  fi

  ENCRYPTION_KEY="${NETBIRD_RECORDER_ENCRYPTION_KEY:-}"
  KEY_GENERATED=false
  if [[ -z "$ENCRYPTION_KEY" ]]; then
    ENCRYPTION_KEY="$(openssl rand -base64 32)"
    KEY_GENERATED=true
  fi

  # Optional login in front of the web UI. Without it, access is controlled by
  # NetBird access policies alone.
  OIDC_ISSUER="$(read_value NETBIRD_RECORDER_OIDC_ISSUER \
    "OIDC issuer URL for a web UI login (leave empty for none)" "" optional)"
  if [[ -n "$OIDC_ISSUER" ]]; then
    OIDC_CLIENT_ID="$(read_value NETBIRD_RECORDER_OIDC_CLIENT_ID "OIDC client ID")"
    OIDC_CLIENT_SECRET="$(read_value NETBIRD_RECORDER_OIDC_CLIENT_SECRET "OIDC client secret")"
    OIDC_ALLOWED_GROUPS="$(read_value NETBIRD_RECORDER_OIDC_ALLOWED_GROUPS \
      "Groups allowed to log in, comma-separated (leave empty to allow any user)" "" optional)"
    SESSION_SIGNING_KEY="$(openssl rand -base64 32)"
  fi
}

check_existing() {
  local f found=()
  for f in docker-compose.yml docker-compose.yaml recorder.env postgres.env; do
    [[ -e "$f" ]] && found+=("$f")
  done
  if [[ ${#found[@]} -gt 0 ]]; then
    echo "Recorder configuration files already exist in the current directory:" >&2
    printf '  %s\n' "${found[@]}" >&2
    echo "" >&2
    echo "Move or remove them, or run this installer in an empty directory." >&2
    exit 1
  fi
}

render_files() {
  log "Generating configuration files..."

  local postgres_service="" postgres_depends="" postgres_volume=""
  if [[ "$BUNDLED_POSTGRES" == "true" ]]; then
    postgres_service="
  postgres:
    image: ${POSTGRES_IMAGE}
    container_name: netbird-recorder-postgres
    <<: *default
    env_file:
      - ./postgres.env
    healthcheck:
      test: [\"CMD-SHELL\", \"pg_isready -U \$\$POSTGRES_USER -d \$\$POSTGRES_DB\"]
      interval: 5s
      timeout: 5s
      retries: 10
    volumes:
      - postgres:/var/lib/postgresql
"
    postgres_depends="
    depends_on:
      postgres:
        condition: service_healthy"
    postgres_volume="
  postgres:
    name: netbird-recorder-postgres
    driver: local"
  fi

  cat > docker-compose.yml <<EOF
# NetBird SSH session recorder (generated by install-recorder.sh)

x-default: &default
  restart: unless-stopped
  networks:
    - netbird-recorder
  logging:
    driver: "json-file"
    options:
      max-size: "50m"
      max-file: "5"

services:${postgres_service}
  recorder:
    image: ${RECORDER_IMAGE}
    container_name: netbird-recorder
    <<: *default
    env_file:
      - ./recorder.env
    cap_add:
      - NET_ADMIN
    volumes:
      # Recordings, their metadata, and this peer's NetBird registration.
      - recorder:/var/lib/netbird-recorder${postgres_depends}

volumes:
  recorder:
    name: netbird-recorder
    driver: local${postgres_volume}

networks:
  netbird-recorder:
    name: netbird-recorder
    driver: bridge
EOF

  (
    umask 077
    cat > recorder.env <<EOF
# NetBird SSH session recorder

NB_LOG_LEVEL=info
NB_MANAGEMENT_URL=${MANAGEMENT_URL}
NB_SETUP_KEY=${SETUP_KEY}
NB_DEVICE_NAME=${DEVICE_NAME}
NB_GRPC_PORT=${GRPC_PORT}
NB_HTTP_ADDRESS=:${HTTP_PORT}
NB_RETENTION_DAYS=${RETENTION_DAYS}
# Encrypts recordings and metadata at rest. Recordings cannot be read without
# it: keep a copy somewhere safe.
NB_ENCRYPTION_KEY=${ENCRYPTION_KEY}
# Recording index database
NB_STORE_ENGINE=${STORE_ENGINE}
EOF
    if [[ "$STORE_ENGINE" == "postgres" ]]; then
      echo "NB_RECORDER_POSTGRES_DSN=${POSTGRES_DSN}" >> recorder.env
    fi
    if [[ "$BUNDLED_POSTGRES" == "true" ]]; then
      cat > postgres.env <<EOF
POSTGRES_DB=recorder
POSTGRES_USER=recorder
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
EOF
    fi
    if [[ -n "$OIDC_ISSUER" ]]; then
      cat >> recorder.env <<EOF
# Web UI login
NB_OIDC_ISSUER=${OIDC_ISSUER}
NB_OIDC_CLIENT_ID=${OIDC_CLIENT_ID}
NB_OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
NB_OIDC_ALLOWED_GROUPS=${OIDC_ALLOWED_GROUPS}
NB_SESSION_SIGNING_KEY=${SESSION_SIGNING_KEY}
EOF
    fi
  )
}

# wait_for_recorder waits until the recorder has joined the network and opened
# its ports, and sets RECORDER_IP from its log.
wait_for_recorder() {
  log "Waiting for the recorder to join the NetBird network..."

  local retries=0 max_retries=60 line
  while true; do
    line="$(docker logs netbird-recorder 2>&1 | grep -o 'recorder: NetBird IP [^,]*' | tail -n 1 || true)"
    if [[ -n "$line" ]]; then
      RECORDER_IP="${line##* }"
      echo "Recorder joined the network as ${RECORDER_IP}."
      return 0
    fi

    if [[ "$(docker inspect netbird-recorder --format '{{.State.Running}}' 2>/dev/null || true)" != "true" ]] &&
      [[ "$retries" -ge 5 ]]; then
      break
    fi

    retries=$((retries + 1))
    [[ "$retries" -lt "$max_retries" ]] || break
    sleep 2
  done

  echo "" >&2
  echo "The recorder did not join the network. Recent logs:" >&2
  docker logs --tail=50 netbird-recorder 2>&1 || true
  echo "" >&2
  die "Check the management URL and that the setup key is valid and unused."
}

start_recorder() {
  log "Starting the NetBird SSH session recorder..."
  $DOCKER_COMPOSE up -d
  wait_for_recorder

  # The OIDC callback URL contains the recorder's NetBird IP, known only now.
  if [[ -n "$OIDC_ISSUER" ]]; then
    OIDC_REDIRECT_URL="http://${RECORDER_IP}:${HTTP_PORT}/auth/callback"
    echo "NB_OIDC_REDIRECT_URL=${OIDC_REDIRECT_URL}" >> recorder.env
    log "Restarting the recorder with the login callback URL..."
    $DOCKER_COMPOSE up -d --force-recreate
    wait_for_recorder
  fi
}

show_results() {
  cat <<EOF

==========================================
NetBird SSH session recorder installed
==========================================

Recorder NetBird IP: ${RECORDER_IP}
Web UI:              http://${RECORDER_IP}:${HTTP_PORT}   (reachable over NetBird only)

Record a peer's SSH sessions by running on that peer:

  netbird up --allow-server-ssh --ssh-session-recorder ${RECORDER_IP}

Then allow that peer to reach the recorder on TCP ${GRPC_PORT} with a NetBird
access policy. Once configured, SSH to that peer is refused whenever the
recorder cannot be reached: recording is never skipped silently.
EOF

  if [[ -n "$OIDC_ISSUER" ]]; then
    cat <<EOF

Web UI login: register this callback URL with your identity provider:

  ${OIDC_REDIRECT_URL}
EOF
  fi

  if [[ "$KEY_GENERATED" == "true" ]]; then
    cat <<EOF

IMPORTANT: recordings are encrypted with a newly generated key, stored as
NB_ENCRYPTION_KEY in $(pwd)/recorder.env. Back it up: recordings cannot be read
without it.
EOF
  fi

  local database="SQLite, on the netbird-recorder volume"
  [[ "$STORE_ENGINE" == "postgres" ]] && database="your PostgreSQL database (NB_RECORDER_POSTGRES_DSN in recorder.env)"
  [[ "$BUNDLED_POSTGRES" == "true" ]] && database="PostgreSQL, in the netbird-recorder-postgres container and volume"
  cat <<EOF

Recording index: ${database}.

The Docker volume netbird-recorder holds the recordings and this peer's NetBird
registration. Removing it makes the recorder register again, which needs a
setup key that can still be used.

==========================================
EOF
}

main() {
  check_dependencies
  check_existing
  configure
  render_files
  start_recorder
  show_results
}

main "$@"
