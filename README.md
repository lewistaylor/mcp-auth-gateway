# MCP Auth Gateway

OAuth 2.1 authentication gateway for MCP servers. Validates JWT access
tokens from Auth0 and proxies authenticated requests to internal MCP
backend services on Railway private networking.

Works with **Claude Desktop**, **claude.ai**, and **Claude mobile** — any
client that supports the MCP OAuth authorization flow.

## How it works

```
Claude Client
    │
    ├─ 1. GET /.well-known/oauth-protected-resource  →  discovers Auth0
    ├─ 2. OAuth flow with Auth0 (PKCE + DCR)          →  gets JWT
    └─ 3. POST /xero/mcp  [Authorization: Bearer JWT] →  gateway validates
                                                            │
                                               ┌────────────┘
                                               ▼
                                     xero-mcp.railway.internal:8000/mcp
```

Route convention: `/<service>/...` proxies to `<service>-mcp.railway.internal:8000/...`

## Auth0 setup

1. Create an [Auth0 account](https://auth0.com/signup) (free tier)
2. In **Settings → Advanced**, enable:
   - **Resource Parameter Compatibility Profile**
   - **Dynamic Client Registration**
3. Promote your database connection to domain-level:
   ```bash
   auth0 api patch connections/YOUR_CONNECTION_ID \
     --data '{"is_domain_connection": true}'
   ```
4. Create an API (**Applications → APIs → Create API**):
   - **Identifier**: your gateway's public URL with trailing slash
     (e.g. `https://mcp-auth-gateway-production-XXXX.up.railway.app/`)
   - **Signing Algorithm**: RS256

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH0_DOMAIN` | Yes | — | Auth0 tenant domain (e.g. `myapp.us.auth0.com`) |
| `AUTH0_AUDIENCE` | Yes | — | API identifier — must match the gateway's public URL |
| `PORT` | No | `8000` | Port the gateway listens on |
| `INTERNAL_SUFFIX` | No | `-mcp.railway.internal` | DNS suffix for backend services |
| `INTERNAL_PORT` | No | `8000` | Port backend services listen on |

## Deploy on Railway

1. Create a new service from this repo
2. Set `AUTH0_DOMAIN` and `AUTH0_AUDIENCE` as environment variables
3. Add a public domain
4. Use that domain (with trailing `/`) as the Auth0 API identifier

Backend MCP services (xero-mcp, clockify-mcp, etc.) should have **no
public domain** — only reachable via Railway private networking.

## Claude Desktop config

```json
{
  "mcpServers": {
    "xero": {
      "url": "https://your-gateway.up.railway.app/xero/mcp"
    },
    "clockify": {
      "url": "https://your-gateway.up.railway.app/clockify/mcp"
    }
  }
}
```

## Local development

```bash
cp .env.example .env
# Edit .env with your Auth0 credentials
npm install
npm start
```

## Tests

```bash
npm test
```
