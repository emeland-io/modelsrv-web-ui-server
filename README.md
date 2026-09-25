# modelsrv-web-ui-server

A modelsrv instance that additionally provides the EmELand web UI and OIDC authentication.

Like all EmELand modules (git-sensor, k8s-sensor, etc.), this embeds modelsrv as a library. The distinguishing feature is the web UI and OIDC auth layer it adds on top.

## Features

- Full modelsrv API (`/api/`, `/swagger/`, `/metrics`)
- File sensor for loading YAML model definitions from disk
- Event subscriber mechanism for receiving data from upstream sensors
- OIDC JWT validation with ownership visibility enforcement
- SPA static file serving with index.html fallback
- `/auth/config.json` endpoint for frontend OIDC discovery
- `/auth/token` proxy for token exchange (avoids CORS)
- `--no-auth` flag for development/demo without authentication

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | `LISTEN_ADDR` | `:8080` | Server listen address |
| `--data-dir` | `DATA_DIR` | (disabled) | Directory to watch for YAML model definitions |
| `--static-dir` | `STATIC_DIR` | (disabled) | UI static files directory |
| `--issuer-url` | `OIDC_ISSUER_URL` | (empty) | OIDC issuer URL |
| `--client-id` | `OIDC_CLIENT_ID` | `emeland-ui` | OIDC client ID |
| `--auditor-group` | `AUDITOR_GROUP_ID` | (empty) | Auditor group UUID (full access) |
| `--public-resource-types` | `PUBLIC_RESOURCE_TYPES` | (empty) | Comma-separated resource types always visible |
| `--no-auth` | `NO_AUTH` | false | Disable authentication (`true`/`false`, `1`/`0`; `NO_AUTH=false` keeps auth on) |
| `--log-level` | `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `--log-encoding` | `LOG_ENCODING` | `json` | Log encoding (`json` or `console`) |

### Logging

A single zap logger is shared with the embedded modelsrv library, so one stream carries:

- Application lifecycle (startup, shutdown, OIDC and file sensor setup)
- HTTP requests handled by the modelsrv API (`/api/`); `/swagger/` and `/metrics` log at `debug`
- OIDC token exchange via `/auth/token` (success at `info`, IdP rejections at `warn`)
- File sensor activity, including documents skipped because of validation errors
- Event manager subscriber notification failures
- modelsrv internals that write via the std `log` package (redirected into zap)

Use `--log-encoding console` for readable local development output, and `--log-level debug`
to include static asset and infrastructure requests.

## Getting Started

### Prerequisites

- Go 1.25+

### Build & Run Locally

```bash
make build

# Run without auth (development mode)
./modelsrv-web-ui-server --no-auth --data-dir ./data

# Run with OIDC
./modelsrv-web-ui-server \
  --issuer-url http://localhost:5556/dex \
  --client-id emeland-ui \
  --auditor-group <group-uuid> \
  --data-dir ./data
```

### Serve Static UI

```bash
./modelsrv-web-ui-server --static-dir ./static --no-auth
```

### Docker

```bash
docker build -t emeland-web-ui-server .

# Build with a specific UI version (default is the UI_VERSION ARG in Dockerfile)
docker build --build-arg UI_VERSION=v0.4.1-rc1 -t emeland-web-ui-server .
```

### Container images (GHCR)

Images are published to `ghcr.io/emeland-io/modelsrv-web-ui-server`:

| Trigger | Image tags |
|---------|------------|
| Push to `main` | `latest`, `main`, `sha-<commit>` |
| GitHub Release published | semver tags from the release (e.g. `v0.1.0`, `0.1.0`, `0.1`, `0`); stable releases also get `latest` |
| Manual (`workflow_dispatch`) | same as above depending on ref; optional `ui_version` input to override the Dockerfile default |

The bundled emeland-ui version defaults to the `UI_VERSION` build arg in the [Dockerfile](Dockerfile). Update that ARG when bumping the UI dependency.

## Architecture

```
Browser -> [OIDC JWT] -> [X-Auth-* header injection] -> modelsrv landscape API (/api/landscape/...)
       \-> SPA static files (/)
       \-> /auth/config.json, /auth/token (OIDC helpers)

Sensors/filter -> POST /api/events/push (no JWT; in-cluster replication) -> modelsrv handler
```

Dex/OIDC protects browser access to the landscape API. `POST /api/events/push` stays
unauthenticated so in-cluster filter and sensor replication can push without a user token.
Cluster networking (ClusterIP / NetworkPolicy) is the intended boundary for that path.

Data also flows in from YAML files watched by the built-in file sensor.

## Development

```bash
make ci        # full check: download, verify, lint, build, test
make test      # run tests only
make lint      # run golangci-lint
```
