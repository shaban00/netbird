# NetBird SSH Session Recorder

A standalone NetBird peer that records SSH sessions streamed to it by other peers running NetBird's embedded SSH server, for audit and compliance.

## How it works

The recorder is an ordinary NetBird peer — architecturally the same idea as `proxy/`, just serving a different purpose. It registers with your NetBird management server like any other peer, gets its own NetBird IP, and listens on two tunnel-bound ports:

- **gRPC, default port `22023`** — SSH-server peers stream session output here.
- **HTTP, default `:8080`** — serves a web UI and JSON API for browsing and playing back recordings.

Recording is a **local, per-SSH-server opt-in**, not a management policy. On each peer that should record its SSH sessions, run `netbird up` with:

```
--allow-server-ssh --ssh-session-recorder <recorder peer's NetBird IP>
```

Once set, every SSH session accepted by that peer's embedded SSH server is recorded — there is no per-user or per-rule granularity. When a session starts, the SSH server streams PTY **output only** to the recorder over gRPC.  The recorder cross-checks the stream's claimed peer ID against the real tunnel-source IP (via NetBird's own peer identity resolution) before accepting a session, so one peer can't submit a recording and attribute it to another.

**Fail-closed by design**: if `--ssh-session-recorder` is set and the recorder is unreachable, misbehaves, or a session exceeds its configured size/duration limit, the SSH session itself is denied — recording is never silently skipped. SFTP and port forwarding are also denied outright on a recording-enabled SSH server, since neither produces output that fits into an asciicast recording.

Each session is written as an [asciicast v3](https://docs.asciinema.org/manual/asciicast/v3/) `.cast` file, encrypted in fixed-size chunks as it streams to disk (not buffered in memory, so recording works for long-running or interrupted sessions too). A session still being recorded can be watched live in the web UI over a websocket, and finished sessions play back through [asciinema-player](https://github.com/asciinema/asciinema-player) embedded in the UI.

Access to the web UI/API is controlled by network reachability (NetBird ACLs) by default. Optionally, set `--oidc-issuer` (and the related `--oidc-*`/`--session-*` flags) to put a real login in front of it.

## Deploying the recorder

### Docker

Images are published as `netbirdio/recorder` and `ghcr.io/netbirdio/recorder`.

```yaml
services:
  recorder:
    image: netbirdio/recorder:latest
    restart: unless-stopped
    environment:
      NB_MANAGEMENT_URL: https://api.netbird.io:443
      NB_SETUP_KEY: <setup key for this peer>
      NB_ENCRYPTION_KEY: <base64 32-byte key, e.g. `openssl rand -base64 32`>
    volumes:
      - recorder-data:/var/lib/netbird-recorder
    cap_add:
      - NET_ADMIN

volumes:
  recorder-data:
```

The data volume holds both the recorder's metadata DB/recordings *and* this peer's own NetBird client registration state — wiping it forces the peer to re-register, which fails if the setup key has already been consumed.

## Configuration reference

Every flag has a matching `NB_<FLAG_NAME>` environment variable (dashes become underscores, uppercased) — e.g. `--management-url` is `NB_MANAGEMENT_URL`, `--max-session-bytes` is `NB_MAX_SESSION_BYTES`.

### Core

| Flag | Default | Description |
| --- | --- | --- |
| `--log-level` | `info` | Log level: panic, fatal, error, warn, info, debug, trace |
| `--log-file` | `console` | Log file path, or `console` for stdout |
| `--device-name` | `netbird-recorder` | This peer's device name |
| `--management-url` | `https://api.netbird.io:443` | Management server address |
| `--setup-key` | _(none)_ | Setup key used to register this peer |
| `--preshared-key` | _(none)_ | Pre-shared key for the tunnel |
| `--data-dir` | `/var/lib/netbird-recorder` | Directory for the metadata DB (sqlite), recording files, and this peer's own NetBird client config |
| `--grpc-port` | `22023` | Tunnel-bound port SSH server peers stream recordings to |
| `--http-address` | `:8080` | Tunnel-bound address serving the JSON API and web UI |
| `--store-engine` | `sqlite` | Metadata store engine: `sqlite` or `postgres` |
| `--encryption-key` | _(none, required)_ | Base64-encoded 32-byte key encrypting metadata fields and `.cast` file contents at rest. Generate with `openssl rand -base64 32` |

### Limits and retention

| Flag | Default | Description |
| --- | --- | --- |
| `--max-session-bytes` | 10 GiB | Maximum recorded output for a single session before the recorder cuts it off (ends the SSH session, not just the recording) |
| `--max-session-duration` | 168h (7 days) | Maximum wall-clock duration for a single session recording |
| `--max-concurrent-sessions` | 128 | Maximum recording sessions open at once across all producers, bounding total disk use |
| `--max-sessions-per-peer` | 32 | Maximum concurrent sessions from one verified peer identity, so one peer can't exhaust the whole pool |
| `--retention-days` | 0 (forever) | Delete a finished session's metadata and recording this many days after it started; a still-recording session is never deleted regardless of age |

### Web UI login (optional)

Unset by default — access is controlled purely by network/ACL reachability. Setting `--oidc-issuer` turns on login and then requires the other `--oidc-*`/`--session-signing-key` flags below.

| Flag | Default | Description |
| --- | --- | --- |
| `--oidc-issuer` | _(none)_ | OIDC issuer URL. Setting this enables login |
| `--oidc-client-id` | _(none)_ | OIDC client ID (required if `--oidc-issuer` is set) |
| `--oidc-client-secret` | _(none)_ | OIDC client secret (required if `--oidc-issuer` is set) |
| `--oidc-redirect-url` | _(none)_ | OAuth callback URL registered with the IdP, e.g. `http://<recorder-ip>:8080/auth/callback` |
| `--oidc-scopes` | `openid profile email` | OIDC scopes to request |
| `--oidc-groups-claim` | `groups` | ID token claim carrying group memberships |
| `--oidc-allowed-groups` | _(none, any user allowed)_ | Comma-separated group names/IDs allowed to log in. A user with none of these groups is denied. Gates login only, not individual sessions — anyone admitted can see every session |
| `--session-signing-key` | _(none, required if OIDC set)_ | Base64-encoded 32-byte key signing the session cookie |
| `--session-cookie-secure` | `false` | Set the cookie's `Secure` flag; enable only behind a reverse proxy terminating real TLS |
| `--session-duration` | `12h` | How long a login session lasts before re-authentication |

## Configuring an SSH server peer to record

On the peer whose SSH sessions should be recorded:

```
netbird up --allow-server-ssh --ssh-session-recorder <recorder's NetBird IP>
```

Optional: `--disable-recorder-banner` suppresses the login banner normally shown to SSH clients when recording is active.

Make sure a NetBird ACL rule allows that peer to reach the recorder on its gRPC port (`22023` by default) — recording-related flags don't create network reachability by themselves. If the recorder becomes unreachable after this is configured, SSH access to that peer is denied rather than silently unrecorded.
