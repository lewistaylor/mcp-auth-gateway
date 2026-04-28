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
| `PUBLIC_SERVICE_PATHS` | No | _empty_ | Comma-separated `<service>:<path>` pairs proxied without Bearer auth (see below) |
| `MCPAUTH_ACCESS_TOKEN_LIFETIME` | No | `86400` | Access token lifetime, seconds. See [Token lifetimes](#token-lifetimes). |
| `MCPAUTH_REFRESH_TOKEN_LIFETIME` | No | `2592000` | Refresh token lifetime, seconds (default 30 days) |
| `UPSTREAM_TIMEOUT_MS` | No | `30000` | Proxy request timeout before returning 502 |
| `BACKEND_SERVICES` | No | _empty_ | Comma-separated list of backend service names (without `-mcp` suffix) that `/health` should probe, e.g. `gmail,gmail-work,notion,xero` |
| `HEALTH_CHECK_TIMEOUT_MS` | No | `2000` | Per-backend timeout for the `/health` readiness probe |

### Public service paths

Some upstream services expose endpoints that legitimately need to be reachable
without a Bearer token — most commonly, OAuth callback URLs that are invoked
by a third-party identity provider's browser redirect. For those, set:

```
PUBLIC_SERVICE_PATHS=gmail:/oauth2callback,gmail:/auth/start
```

Path matching is **exact** (no prefixes, no wildcards). Query strings are
ignored. Only list paths whose upstream implementation is safe to expose
publicly — typically endpoints already protected by application-layer
mechanisms such as OAuth `state`/PKCE validation or a shared setup token.

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

## Observability

### Structured request logs

Every proxy request emits a single-line JSON log entry on response
finish. Railway scrapes stdout, so these lines are directly queryable
in the Railway logs UI.

Fields:

| Field | Type | Notes |
|---|---|---|
| `ts` | string | ISO-8601 timestamp |
| `level` | string | `info` for 2xx/3xx/4xx, `error` for 5xx / upstream errors |
| `msg` | string | Always `proxy request` for proxy logs |
| `srcIp` | string | Client IP (honours `X-Forwarded-For` — `trust proxy` is on) |
| `method` | string | HTTP method |
| `path` | string | Gateway path, including query string |
| `service` | string | Service segment (e.g. `gmail-work`) |
| `public` | boolean | True if the path bypassed Bearer validation |
| `hasBearer` | boolean | Whether the request carried a Bearer header (token value is **never** logged) |
| `mcpSessionId` | string\|null | Value of the `Mcp-Session-Id` request header |
| `userId` | string\|null | Subject from the validated OAuth token, if any |
| `status` | number | Status returned to the client |
| `upstreamStatus` | number\|null | Status returned by the upstream MCP service |
| `upstreamError` | string\|null | `socket-timeout`, `upstream-timeout`, `connection-refused`, `connection-reset`, `host-unreachable`, `dns-failure`, or the raw errno code |
| `authReason` | string\|null | `no-bearer-header` or `invalid-or-expired-token` on a 401; null otherwise |
| `durationMs` | number | Time from request arrival to response finish |
| `userAgent` | string | Client UA string |

Bodies — request and response — are **never** logged. Gmail / Xero
content is considered sensitive.

In addition, the gateway emits a separate `auth rejected` log line
the moment a Bearer validation fails, with these fields:

| Field | Notes |
|---|---|
| `srcIp` | Client IP |
| `path` | Gateway path being probed |
| `reason` | One of: `no-bearer-header`, `malformed-bearer`, `unknown-to-db`, `expired`, `lookup-failed`, `bad-expiry` |
| `hasBearer` | Whether an `Authorization: Bearer …` header was present |
| `tokenPrefix` | First 6 characters of the token (for correlating repeat offenders — **never** the full token) |
| `userAgent` | Client UA string |

This is the trail to grep when:

- **Watching for "Gmail drops out"** — `reason:"expired"` means the
  client's refresh flow failed / didn't run in time.
- **Watching for credential stuffing or scanner traffic** —
  `reason:"unknown-to-db"` or `reason:"no-bearer-header"` from an
  unexpected `srcIp` / `userAgent`.
- **Diagnosing client misconfigurations** — `reason:"malformed-bearer"`
  usually means the client is setting the header but sending an empty
  token (config-file typo, unset env var).
- **Spotting infra issues** — `reason:"lookup-failed"` means the
  SQLite store threw during the auth path; alert on this.

### `/health` contract

`GET /health` is a **readiness** probe. It returns:

- `200` with `{"status":"ok","checks":{...}}` when all dependencies
  are healthy
- `503` with `{"status":"degraded","checks":{...}}` when any
  dependency fails

Checks performed:

- `database` — `SELECT 1` against the SQLite database
- `backends.<service>` (only if `BACKEND_SERVICES` is set) — `GET /`
  to each listed backend, with `HEALTH_CHECK_TIMEOUT_MS` per probe

`GET /` is kept as a trivial liveness probe (plain text `ok`) for
fast Railway HTTP healthchecks.

### Upstream timeouts

All proxy requests are bounded by `UPSTREAM_TIMEOUT_MS` (default 30s)
so the gateway does not hang indefinitely on an unresponsive backend.
On timeout, the gateway returns `502` with JSON-RPC
`{ "error": { "code": -32000, "message": "Upstream timeout" } }`, and
emits an `upstream error` log line including `targetUrl`, `errorKind`,
and `waitedMs`.

### Sessions and the `-32002` contract

Backend MCP services keep their session map **in memory**, so every
Railway redeploy of an upstream service (gmail-mcp, notion-mcp, …)
wipes every active session for that service. This is an explicit
design choice — the alternative would be wiring Redis or Postgres
into every backend just to survive deploys, which is a lot of moving
parts for a self-hosted gateway.

What makes the wipe survivable is the streamable HTTP transport's
`-32002 "Session terminated"` signal. Three cases, one contract:

1. **Idle session reap (TTL).** Backend returns `404 + JSON-RPC
   -32002`; gateway forwards it verbatim. Client reinitializes.
2. **Upstream redeploy completed.** New container has an empty session
   map, sees the client's stale `Mcp-Session-Id`, returns `404 +
   -32002`; gateway forwards it verbatim. Client reinitializes.
3. **Upstream redeploy in flight.** Old container is gone, new one
   isn't listening yet, so the gateway sees `ECONNREFUSED` /
   `ECONNRESET` / `ENOTFOUND` / timeout. **The gateway synthesizes
   `404 + -32002` itself** — but only when the request carried an
   `Mcp-Session-Id`. Without a session id (i.e. an `initialize`
   attempt), the gateway returns the truthful `502 + -32000` because
   there is no session to terminate and the client cannot do anything
   useful with a fake -32002.

Cases 1, 2, and 3 are byte-for-byte indistinguishable to the MCP
client, which means Claude / Cursor recover automatically across an
upstream redeploy. Synthesis events show up in the request log as
`msg:"synthesized session-terminated"` so operators can spot redeploy
windows.

The recoverable error categories are pinned in
`lib/jsonrpc.mjs → RECOVERABLE_UPSTREAM_ERRORS`. Add new categories
deliberately — anything in that set is presented to the client as
"your session is gone", and lying about that would put clients into a
reinit loop.

### Token lifetimes

| Token | Default | Env var | Notes |
|---|---|---|---|
| Access token | 24h (86400s) | `MCPAUTH_ACCESS_TOKEN_LIFETIME` | Override to shorten if you need tighter revocation windows |
| Refresh token | 30d (2592000s) | `MCPAUTH_REFRESH_TOKEN_LIFETIME` | Governs how often a client must redo the full OAuth flow |

The 24-hour / 30-day defaults are a tradeoff: longer-lived tokens
reduce session churn for long-running agent clients (Claude Desktop,
Cursor) but give a larger blast radius if one leaks and a longer
window before a compromised client gets cut off. If that tradeoff
matters for your deployment, set `MCPAUTH_ACCESS_TOKEN_LIFETIME=3600`
(or shorter) and/or `MCPAUTH_REFRESH_TOKEN_LIFETIME=1209600` (14d)
and rely on refresh-token rotation.

## Smoke test

`scripts/smoke-test.mjs` drives a minimal end-to-end sequence — health
check, MCP `initialize`, `tools/list` — against a deployed gateway and
reports per-step latency and status. Useful for post-deploy sanity
checks and for reproducing the "400 after OAuth reconnect" failure
mode.

```bash
BASE_URL=https://your-gateway.up.railway.app \
BEARER_TOKEN=<paste access_token from POST /api/oauth/token> \
SERVICE=gmail-work \
npm run smoke
```

The script exits `0` when every step returned a non-5xx status AND
the `initialize` response included an `Mcp-Session-Id` header;
non-zero otherwise, so it can be wired into CI or a cron alert.
The Bearer token is read from the environment and is never written
to stdout. Response bodies are truncated to 500 characters to bound
accidental leakage of upstream content.
