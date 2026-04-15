# MCP Auth Gateway

Self-hosted OAuth 2.1 authentication gateway for MCP servers. Embeds
[@mcpauth/auth](https://github.com/mcpauth/mcpauth) as the authorization
server with a simple login page. No external auth provider needed.

Works with **Claude Desktop**, **claude.ai**, **Claude mobile**, and **Cursor**.

## How it works

```
Claude/Cursor Client
    │
    ├─ 1. POST /xero/mcp                          → 401 Unauthorized
    ├─ 2. GET /.well-known/oauth-protected-resource → discovers auth server
    ├─ 3. POST /api/oauth/register                 → Dynamic Client Registration
    ├─ 4. GET /api/oauth/authorize                 → redirects to /login
    ├─ 5. User logs in at /login                   → session cookie set
    ├─ 6. Consent + auth code issued               → client gets code
    ├─ 7. POST /api/oauth/token                    → JWT access token
    └─ 8. POST /xero/mcp [Authorization: Bearer]   → validated + proxied
                                                       │
                                          xero-mcp.railway.internal:8000/mcp
```

### Route convention

`/<service>/...` proxies to `<service>-mcp.railway.internal:<INTERNAL_PORT>/...`

The service name in the URL path maps to the Railway private domain. For
example, `/charlie/mcp` routes to `charlie-mcp.railway.internal:8000/mcp`.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `BASE_URL` | Yes | — | Gateway's public URL (no trailing slash) |
| `GATEWAY_USERNAME` | Yes | — | Login username |
| `GATEWAY_PASSWORD` | Yes | — | Login password |
| `MCPAUTH_SECRET` | Yes | — | Secret for OAuth state signing |
| `MCPAUTH_PRIVATE_KEY` | Yes | — | RSA private key for JWT signing (PEM) |
| `DATABASE_PATH` | No | `./data/db.sqlite` | SQLite database path |
| `PORT` | No | `8000` | Listen port |
| `INTERNAL_SUFFIX` | No | `-mcp.railway.internal` | Backend DNS suffix |
| `INTERNAL_PORT` | No | `8000` | Backend port (must match backend services) |

## Generate secrets

```bash
# RSA private key for JWT signing
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048

# State secret
openssl rand -hex 32
```

## Deploy on Railway

1. Create a service from this repo.
2. Add a **volume** mounted at `/app/data` (for SQLite persistence).
3. Add a **public domain**.
4. Set env vars: `BASE_URL` (= public domain with `https://`),
   `GATEWAY_USERNAME`, `GATEWAY_PASSWORD`, `MCPAUTH_SECRET`,
   `MCPAUTH_PRIVATE_KEY`.

Backend MCP services (xero-mcp, clockify-mcp, etc.) should have **no
public domain** — only reachable via Railway private networking.

## Claude/Cursor config

Once deployed, add MCP servers using the gateway URL:

```
https://your-gateway.up.railway.app/xero/mcp
https://your-gateway.up.railway.app/clockify/mcp
https://your-gateway.up.railway.app/charlie/mcp
https://your-gateway.up.railway.app/opensign/mcp
```

Claude handles the OAuth flow automatically — it discovers the auth
server, registers via DCR, and opens a browser for login.

## Adding a new backend MCP service

Follow this checklist when adding a new MCP server behind the gateway:

### 1. Build the service

Create a new repo with the standard structure:

```
my-service-mcp/
├── Dockerfile              # Build + run the MCP server
├── railway.toml            # Railway config (healthcheck, restart, no public domain)
├── .env.example            # Env var template
├── .dockerignore           # Exclude node_modules, .git, .env, build, etc.
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts            # Entrypoint — validates creds, starts Express
    ├── transport.ts        # Express app, Streamable HTTP transport, sessions
    ├── my-api.ts           # API client for the target service
    └── tools/
        ├── index.ts        # Registers all tool groups
        └── *.ts            # One file per tool group
```

Use the existing services (`charlie-mcp`, `clockify-mcp`, `opensign-mcp`) as
templates — they share identical structure and dependencies.

### 2. Configure `railway.toml`

```toml
[build]
builder = "DOCKERFILE"
dockerfilePath = "Dockerfile"

[deploy]
healthcheckPath = "/health"
healthcheckTimeout = 120
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 10
```

Do **NOT** add `requiredMountPath` unless the service needs persistent storage
(like xero-mcp for token persistence).

### 3. Deploy to Railway

```bash
# In the Railway project:
railway add --service my-service-mcp --repo your-org/my-service-mcp
railway link --service my-service-mcp

# Pin the port to match the auth gateway's INTERNAL_PORT
railway variables --set "PORT=8000"

# Set service-specific env vars
railway variables --set "MY_API_KEY=xxx"
```

### 4. Verify

The service is now reachable through the auth gateway at:

```
https://<auth-gateway-domain>/my-service/mcp
```

No changes to the auth gateway are needed — it auto-discovers backend
services based on the URL path convention.

### Key requirements

- **Port**: Backend services **must** listen on port `8000` (or whatever
  `INTERNAL_PORT` is set to on the gateway). Set `PORT=8000` as a Railway
  env var.
- **No public domain**: Backend services must only be reachable via Railway
  private networking. The auth gateway is the only public-facing service.
- **Health endpoint**: Expose a health check at the path specified in
  `railway.toml` (typically `/health` or `/`).
- **Naming convention**: The Railway service name determines the route.
  A service named `foo-mcp` is reachable at `/<foo>/mcp` through the gateway,
  which proxies to `foo-mcp.railway.internal:8000`.

## Local development

```bash
cp .env.example .env
# Edit .env with your values
npm install
npm start
```

## Tests

```bash
npm test
```
