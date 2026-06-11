# modelsrv-web-ui-server

A Go HTTP server that sits between the EmELand UI and modelsrv backend, providing authentication, authorization, and static file serving.

## Features

- Reverse proxy to modelsrv backend (`/api/`, `/swagger/`, `/metrics`)
- SPA static file serving with index.html fallback
- OIDC JWT validation via JWKS
- Authorization middleware (auditor = full access, owner = scoped by `emeland.io/owner-context`)
- `/auth/config.json` endpoint for frontend OIDC discovery
- `/auth/token` proxy for token exchange (avoids CORS)
- `--no-auth` flag for development/demo without authentication

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | `LISTEN_ADDR` | `:8080` | Server listen address |
| `--backend` | `BACKEND_URL` | `http://localhost:8081` | modelsrv backend URL |
| `--static-dir` | `STATIC_DIR` | (disabled) | UI static files directory |
| `--issuer-url` | `OIDC_ISSUER_URL` | (empty) | OIDC issuer URL |
| `--client-id` | `OIDC_CLIENT_ID` | `emeland-ui` | OIDC client ID |
| `--auditor-group` | `AUDITOR_GROUP_ID` | (empty) | Auditor group UUID |
| `--no-auth` | `NO_AUTH` | false | Disable authentication |

## Getting Started

### Prerequisites

- Go 1.25+
- A running [modelsrv](https://github.com/emeland-io/modelsrv) instance as backend

### Build & Run Locally

```bash
# Build
make build

# Run without auth (development mode)
make run -- --no-auth --backend http://localhost:8081

# Run with OIDC
go run ./cmd/modelsrv-web-ui-server \
  --backend http://localhost:8081 \
  --issuer-url http://localhost:5556/dex \
  --client-id emeland-ui \
  --auditor-group <group-uuid>
```

### Serve Static UI

To also serve the EmELand UI frontend, pass `--static-dir` pointing to a directory containing the built UI assets:

```bash
go run ./cmd/modelsrv-web-ui-server --static-dir ./static --no-auth
```

### Docker

```bash
# Production image (server only, no UI bundled)
docker build -t emeland-web-ui-server .

# Local/demo image (bundles UI from release)
docker build -f Dockerfile.local -t emeland-web-ui-server:local .
```

## Demo Deployment (KinD)

A demo manifest is provided in `deploy/demo.yaml` that runs the server with a Dex sidecar for local OIDC:

```bash
kubectl create namespace emeland-demo
kubectl apply -f deploy/demo.yaml
kubectl port-forward -n emeland-demo pod/web-ui-server 8080:8080 5556:5556
```

Then open http://localhost:8080 and log in with `admin@emeland.io` / `password`.

## Development

```bash
make ci        # full check: download, verify, lint, build, test
make test      # run tests only
make lint      # run golangci-lint
```
