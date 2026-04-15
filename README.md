# MCP Auth Gateway

Self-hosted OAuth 2.1 authentication gateway for MCP servers. Embeds
[@mcpauth/auth](https://github.com/mcpauth/mcpauth) as the authorization
server with a simple login page. No external auth provider needed.

Works with **Claude Desktop**, **claude.ai**, and **Claude mobile**.

## How it works

```
Claude Client
    |
    +- 1. POST /xero/mcp                          -> 401 Unauthorized
    +- 2. GET /.well-known/oauth-protected-resource -> discovers auth server
    +- 3. POST /api/oauth/register                 -> Dynamic Client Registration
    +- 4. GET /api/oauth/authorize                 -> redirects to /login
    +- 5. User logs in at /login                   -> session cookie set
    +- 6. Consent + auth code issued               -> client gets code
    +- 7. POST /api/oauth/token                    -> JWT access token
    +- 8. POST /xero/mcp [Authorization: Bearer]   -> validated + proxied
                                                       |
                                          xero-mcp.railway.internal:8000/mcp
```

Route convention: `/<service>/...` proxies to `<service>-mcp.railway.internal:8000/...`

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `BASE_URL` | Yes | - | Gateway's public URL (no trailing slash) |
| `GATEWAY_USERNAME` | Yes | - | Login username |
| `GATEWAY_PASSWORD` | Yes | - | Login password |
| `MCPAUTH_SECRET` | Yes | - | Secret for OAuth state signing |
| `MCPAUTH_PRIVATE_KEY` | Yes | - | RSA private key for JWT signing (PEM) |
| `MCPAUTH_ALLOWED_ORIGIN` | No | `*` | CORS allowed origins |
| `DATABASE_PATH` | No | `./data/db.sqlite` | SQLite database path |
| `PORT` | No | `8000` | Listen port |
| `INTERNAL_SUFFIX` | No | `-mcp.railway.internal` | Backend DNS suffix |
| `INTERNAL_PORT` | No | `8000` | Backend port |

## Generate secrets

```bash
# Private key
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048

# State secret
openssl rand -hex 32
```

## Deploy on Railway

1. Create a service from this repo
2. Add a **volume** mounted at `/data` (for SQLite persistence)
3. Add a **public domain**
4. Set env vars: `BASE_URL` (= public domain), `GATEWAY_USERNAME`,
   `GATEWAY_PASSWORD`, `MCPAUTH_SECRET`, `MCPAUTH_PRIVATE_KEY`

Backend MCP services (xero-mcp, clockify-mcp, etc.) should have **no
public domain** — only reachable via Railway private networking.

## Claude config

Once deployed, add MCP servers in Claude using the gateway URL:

```
https://your-gateway.up.railway.app/xero/mcp
https://your-gateway.up.railway.app/clockify/mcp
```

Claude handles the OAuth flow automatically — it discovers the auth
server, registers via DCR, and opens a browser for login.

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
