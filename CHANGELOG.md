# Changelog

All notable changes to the MCP auth gateway are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres loosely to [SemVer](https://semver.org/). Since
the gateway is self-hosted with a single consumer, version bumps track
deployments rather than a formal release cadence.

## [Unreleased] — 2026-04-24 — Observability

Motivated by two incidents on 17 and 24 April 2026:

- **Mode 1 — upstream hangs producing 502s:** ~20+ `POST /gmail/mcp`
  requests at 09:56:05 on 24 April all returned 502 after 15-minute
  durations. Node's default socket timeout is effectively infinite,
  so the gateway was happy to sit on a hung `gmail-mcp` connection
  for a quarter of an hour before giving up.
- **Mode 2 — 400s after OAuth reconnect:** after a fresh
  `POST /api/oauth/token` returning 200, subsequent `/gmail-work/mcp`
  requests returned 400, surfaced as "Error occurred during tool
  execution". The most likely cause is an `Mcp-Session-Id` mismatch
  (client carrying a stale session id after upstream restart); item
  6 of the accompanying issue on `lewistaylor/gmail-mcp` tracks the
  upstream remediation.

### Added

- **Structured JSON request logs** — every proxy request now emits a
  single-line JSON log on response finish, with `srcIp`, `method`,
  `path`, `service`, `hasBearer`, `mcpSessionId`, `userId`, `status`,
  `upstreamStatus`, `upstreamError`, `authReason`, `durationMs`, and
  `userAgent`. Tokens, cookies, and request / response bodies are
  never logged.
- **Auth-outcome logs** — every 401 rejection emits a dedicated
  `auth rejected` log line with `reason`
  (`no-bearer-header` or `invalid-or-expired-token`). Gateway login
  failures emit a `gateway login failed` log line.
- **Real `/health` endpoint** — replaces the trivial `ok` string.
  Verifies SQLite is queryable and (optionally, when
  `BACKEND_SERVICES` is set) probes each registered backend via
  `GET /` with a `HEALTH_CHECK_TIMEOUT_MS` budget. Returns 200 with
  per-dependency JSON on success, 503 otherwise. `GET /` is kept
  trivial for fast liveness checks.
- **Upstream error classification** — the new `classifyUpstreamError`
  helper maps libuv errno codes (`ETIMEDOUT`, `ECONNREFUSED`,
  `ECONNRESET`, `EHOSTUNREACH`, `ENOTFOUND`, …) to stable categories
  (`socket-timeout`, `connection-refused`, `dns-failure`, …) so
  operators can filter Railway logs by failure mode.
- **Smoke test** (`scripts/smoke-test.mjs`, `npm run smoke`) — drives
  `/health` → MCP `initialize` → `tools/list` against a deployed
  gateway and reports per-step latency and status. Suitable for
  post-deploy sanity checks and for reproducing mode 2 locally.
- **Unit tests** (`test/observability.test.mjs`) covering the pure
  helpers (`logJson`, `classifyUpstreamError`, `classify401`).

### Changed

- **Upstream proxy timeout** — requests are now bounded by
  `UPSTREAM_TIMEOUT_MS` (default 30 s) via `proxyReq.setTimeout`.
  Previously the socket had no timeout, which is the direct cause of
  the 15-minute 502 durations in the 24 April incident.
- **Access token lifetime** — bumped from 1 h to 24 h (`86400 s`),
  overridable via the new `MCPAUTH_ACCESS_TOKEN_LIFETIME` env var.
  Refresh-token lifetime stays at 14 days. The tradeoff is
  documented in the README — longer-lived tokens reduce session
  churn but enlarge the blast radius of a leak.
- **Proxy error response on timeout** — when the upstream times out,
  the gateway now returns `{"error":{"code":-32000,"message":"Upstream
  timeout"}}` instead of the generic "Service unavailable" body.
- **Helpers extracted to `lib/observability.mjs`** so they can be
  unit-tested without booting the full gateway (which requires env
  vars + SQLite).

### Fixed

- **Gateway no longer hangs forever on unresponsive upstreams.** The
  default 30-second timeout returns a 502 to the client with a
  classified error log line — operators can now spot the failure
  mode in seconds rather than after a 15-minute gap in the logs.

### Deployment notes

- Set `BACKEND_SERVICES` on Railway (e.g.
  `gmail,gmail-work,notion,xero,clockify,opensign,charlie`) to enable
  the new `/health` readiness probe. Point Railway healthchecks at
  `/health` to get auto-restart on dependency failure.
- No schema migration. The SQLite layout is unchanged.
- `MCPAUTH_ACCESS_TOKEN_LIFETIME` is optional; if unset, the new
  24-hour default applies. Previously-issued 1-hour access tokens
  remain valid for their original expiry — this change only affects
  tokens issued after the deploy.
