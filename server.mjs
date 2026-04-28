#!/usr/bin/env node

/**
 * Self-hosted OAuth 2.1 auth gateway for MCP servers.
 *
 * Embeds @mcpauth/auth as the authorization server (DCR, PKCE, token
 * issuance) with a simple username/password login page. Validates
 * Bearer tokens on proxy routes and forwards authenticated requests
 * to internal MCP backend services on Railway private networking.
 *
 * No external auth provider required — everything runs in this process
 * with SQLite for token/client storage.
 *
 * Route map:
 *   GET  /                                → liveness probe (plain "ok")
 *   GET  /health                          → readiness probe (JSON dep status)
 *   GET  /login                           → login page
 *   POST /login                           → login handler
 *        /api/oauth/*                     → @mcpauth/auth OAuth endpoints
 *        /.well-known/*                   → @mcpauth/auth + RFC 9728 metadata
 *        /<service>/*                     → token-validated proxy to backends
 *
 * All proxy requests emit a single-line JSON log entry on response
 * finish (see `logRequest`). See README.md for the field contract.
 */

import express from "express";
import cookieParser from "cookie-parser";
import { McpAuth, getMcpSession } from "@mcpauth/auth/adapters/express";
import { SqliteAdapter } from "@mcpauth/auth/stores/sqlite";
import { SignJWT, jwtVerify } from "jose";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  logJson,
  classifyUpstreamError,
  classify401Detailed,
} from "./lib/observability.mjs";
import {
  shouldSynthesizeSessionTerminated,
  buildSessionTerminatedBody,
  buildUpstreamErrorBody,
} from "./lib/jsonrpc.mjs";

// ── Config ──────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || "8000";
const BASE_URL = process.env.BASE_URL;
const GATEWAY_USERNAME = process.env.GATEWAY_USERNAME;
const GATEWAY_PASSWORD = process.env.GATEWAY_PASSWORD;
const DATABASE_PATH = process.env.DATABASE_PATH || "./data/db.sqlite";
const INTERNAL_SUFFIX =
  process.env.INTERNAL_SUFFIX || "-mcp.railway.internal";
const INTERNAL_PORT = parseInt(process.env.INTERNAL_PORT || "8000", 10);

/**
 * How long an issued access token is valid, in seconds.
 *
 * Default is 24h (86400). The previous value of 1h caused noticeable
 * session churn for long-running agent use cases (Claude, Cursor).
 * The refresh token lifetime stays at 14d, so a longer access token
 * only shrinks the frequency at which the token endpoint is called —
 * it does not extend the overall grant lifetime.
 *
 * Tradeoff: longer-lived access tokens mean a larger blast radius if
 * one leaks, and a longer window before a compromised client is cut
 * off. Override via MCPAUTH_ACCESS_TOKEN_LIFETIME (seconds) if that
 * tradeoff matters for your deployment.
 */
const ACCESS_TOKEN_LIFETIME = parseInt(
  process.env.MCPAUTH_ACCESS_TOKEN_LIFETIME || "86400",
  10,
);

/**
 * Refresh token lifetime, in seconds. Default is 30 days (2592000).
 * Overridable via MCPAUTH_REFRESH_TOKEN_LIFETIME for deployments that
 * prefer shorter rotation windows.
 *
 * The previous hard-coded 14-day value caused users to hit the full
 * OAuth flow every fortnight even on actively-used clients, which
 * masked the access-token churn issue as a "Gmail dropped out again"
 * symptom. Extending to 30 days matches what Claude / Cursor users
 * typically expect from long-running agent sessions.
 */
const REFRESH_TOKEN_LIFETIME = parseInt(
  process.env.MCPAUTH_REFRESH_TOKEN_LIFETIME || "2592000",
  10,
);

/**
 * Upstream proxy timeout, in milliseconds. Applied via
 * `proxyReq.setTimeout()` so the gateway does not sit on a dead
 * upstream connection indefinitely. (Node's default socket timeout
 * is effectively infinite — see the 15-minute 502 incident on
 * 17 / 24 April 2026.)
 */
const UPSTREAM_TIMEOUT_MS = parseInt(
  process.env.UPSTREAM_TIMEOUT_MS || "30000",
  10,
);

/**
 * List of backend service names (without the `-mcp` suffix) that the
 * /health endpoint should probe for readiness. Matches the service
 * segment used in `/<service>/...` proxy URLs. Comma-separated.
 *
 * Example: `BACKEND_SERVICES=gmail,gmail-work,notion,xero`
 *
 * Unset / empty disables upstream probing; only the SQLite check runs.
 * Unknown services produce a 503 if they fail to respond within
 * HEALTH_CHECK_TIMEOUT_MS.
 */
const BACKEND_SERVICES = (process.env.BACKEND_SERVICES || "")
  .split(",")
  .map((s) => s.trim())
  .filter((s) => s.length > 0);

const HEALTH_CHECK_TIMEOUT_MS = parseInt(
  process.env.HEALTH_CHECK_TIMEOUT_MS || "2000",
  10,
);

/**
 * Paths that should be proxied WITHOUT requiring a Bearer token.
 *
 * Format: comma-separated list of `<service>:<path>` pairs, where `<path>`
 * is the exact path on the upstream service (i.e. after the `/<service>`
 * prefix has been stripped by Express mount routing). Query strings are
 * ignored during matching.
 *
 * Example (enables Gmail's server-side OAuth consent flow):
 *   PUBLIC_SERVICE_PATHS=gmail:/oauth2callback,gmail:/auth/start
 *
 * Use with care — any path listed here is exposed to the public internet
 * without MCP OAuth 2.1 authentication. Only use for endpoints that either
 * (a) are safe to invoke anonymously (e.g. OAuth callbacks, which are
 * secured by state/PKCE at the application layer), or (b) implement their
 * own application-layer authentication.
 */
const PUBLIC_SERVICE_PATHS = new Set(
  (process.env.PUBLIC_SERVICE_PATHS || "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0),
);
if (PUBLIC_SERVICE_PATHS.size > 0) {
  logJson({
    level: "info",
    msg: "public service paths configured",
    paths: [...PUBLIC_SERVICE_PATHS],
  });
}

/**
 * Returns true if the given (service, path) pair is configured to bypass
 * Bearer token validation. Matches the exact path — no prefix matching or
 * wildcards — to prevent accidental exposure of adjacent endpoints.
 */
export function isPublicServicePath(service, path) {
  return PUBLIC_SERVICE_PATHS.has(`${service}:${path}`);
}

for (const v of [
  "BASE_URL",
  "GATEWAY_USERNAME",
  "GATEWAY_PASSWORD",
  "MCPAUTH_PRIVATE_KEY",
  "MCPAUTH_SECRET",
]) {
  if (!process.env[v]) {
    console.error(`[auth-gateway] Fatal: ${v} is required`);
    process.exit(1);
  }
}

// ── Keys ────────────────────────────────────────────────────────────────────

const privateKeyPem = process.env.MCPAUTH_PRIVATE_KEY.replace(/\\n/g, "\n");
const privateKey = createPrivateKey(privateKeyPem);
const publicKey = createPublicKey(privateKey);

// ── Database bootstrap ──────────────────────────────────────────────────────

import Database from "better-sqlite3";

mkdirSync(dirname(DATABASE_PATH), { recursive: true });

const db = new Database(DATABASE_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS oauth_client (
    id                          TEXT PRIMARY KEY,
    client_id                   TEXT UNIQUE NOT NULL,
    client_secret               TEXT,
    name                        TEXT NOT NULL DEFAULT '',
    description                 TEXT,
    logo_uri                    TEXT,
    redirect_uris               TEXT NOT NULL DEFAULT '[]',
    grant_types                 TEXT NOT NULL DEFAULT '[]',
    scope                       TEXT,
    token_endpoint_auth_method  TEXT DEFAULT 'none',
    user_id                     TEXT,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                  TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS oauth_authorization_code (
    authorization_code       TEXT PRIMARY KEY,
    expires_at               TEXT NOT NULL,
    redirect_uri             TEXT NOT NULL,
    scope                    TEXT,
    authorization_details    TEXT,
    code_challenge           TEXT,
    code_challenge_method    TEXT,
    client_id                TEXT NOT NULL REFERENCES oauth_client(id) ON DELETE CASCADE,
    user_id                  TEXT NOT NULL,
    created_at               TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS oauth_token (
    access_token              TEXT PRIMARY KEY,
    access_token_expires_at   TEXT NOT NULL,
    refresh_token             TEXT UNIQUE,
    refresh_token_expires_at  TEXT,
    scope                     TEXT,
    authorization_details     TEXT,
    client_id                 TEXT NOT NULL REFERENCES oauth_client(id) ON DELETE CASCADE,
    user_id                   TEXT NOT NULL,
    created_at                TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
db.close();

// ── @mcpauth/auth setup ─────────────────────────────────────────────────────

const rawAdapter = SqliteAdapter(DATABASE_PATH);

// Workaround: @mcpauth/auth's getClient rejects confidential clients when no
// secret is supplied. The authorize endpoint legitimately calls getClient(id)
// without a secret (per OAuth 2.1 — secret verification happens at the token
// endpoint, not the authorization endpoint). We fall back to a direct DB lookup
// for the no-secret case so that confidential clients can be identified.
const lookupDb = new Database(DATABASE_PATH, { readonly: true });
const lookupStmt = lookupDb.prepare(
  "SELECT * FROM oauth_client WHERE client_id = ?",
);
// Prepared once for the health probe so we don't pay the prepare cost on
// every /health request.
const healthPingStmt = lookupDb.prepare("SELECT 1 AS ok");

// Prepared once for the 401 classifier so each failed request does a
// single indexed lookup (access_token is the PRIMARY KEY).
const tokenLookupStmt = lookupDb.prepare(
  "SELECT access_token_expires_at FROM oauth_token WHERE access_token = ?",
);

/**
 * DB-backed lookup used by `classify401Detailed`. Returns `null` when
 * the token is unknown to the gateway (never issued, revoked, or
 * scanner garbage) and `{ expiresAt }` otherwise. Kept tiny so it's
 * easy to swap for a test double.
 */
function lookupTokenForClassifier(token) {
  const row = tokenLookupStmt.get(token);
  if (!row) return null;
  return { expiresAt: row.access_token_expires_at };
}

function clientRowToObject(row) {
  if (!row) return null;
  const parse = (v) => { try { return JSON.parse(v); } catch { return v; } };
  return {
    id: row.id,
    clientId: row.client_id,
    clientSecret: row.client_secret,
    name: row.name,
    redirectUris: parse(row.redirect_uris),
    grantTypes: parse(row.grant_types),
    scope: row.scope || undefined,
    tokenEndpointAuthMethod: row.token_endpoint_auth_method,
  };
}

const adapter = {
  ...rawAdapter,
  async getClient(clientId, clientSecret) {
    if (clientSecret != null) {
      return rawAdapter.getClient(clientId, clientSecret);
    }
    return clientRowToObject(lookupStmt.get(clientId));
  },
  async registerClient(params) {
    // Force all clients to public (PKCE-only). @mcpauth/auth has a bug where
    // confidential client DCR returns the bcrypt hash instead of the plaintext
    // secret, breaking the token exchange. Public clients with PKCE are the
    // correct model for user-facing MCP clients anyway.
    return rawAdapter.registerClient({
      ...params,
      token_endpoint_auth_method: "none",
    });
  },
};

const mcpAuthConfig = {
  adapter,
  issuerUrl: BASE_URL,
  issuerPath: "/api/oauth",
  serverOptions: {
    accessTokenLifetime: ACCESS_TOKEN_LIFETIME,
    refreshTokenLifetime: REFRESH_TOKEN_LIFETIME,
  },
  authenticateUser: async (req) => {
    // @mcpauth/auth passes a framework-agnostic HttpRequest, not Express Request.
    // Cookies must be parsed from the raw header.
    const cookieHeader = req.headers?.cookie || "";
    const match = cookieHeader.match(/gateway_session=([^;]+)/);
    if (!match) return null;
    try {
      const { payload } = await jwtVerify(match[1], publicKey);
      return { id: payload.sub, name: payload.sub, email: `${payload.sub}@gateway` };
    } catch {
      return null;
    }
  },
  signInUrl: (req, callbackUrl) => {
    const redirect = callbackUrl || req.url;
    return `/login?redirect=${encodeURIComponent(redirect)}`;
  },
};

const mcpAuth = McpAuth(mcpAuthConfig);
const validateToken = getMcpSession(mcpAuthConfig);

// ── Express app ─────────────────────────────────────────────────────────────

const app = express();
app.set("trust proxy", true);
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS",
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Accept, Mcp-Session-Id",
  );
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ── Health ──────────────────────────────────────────────────────────────────

/**
 * Liveness probe — returns 200 as long as the process is accepting
 * connections. Kept trivial so Railway's HTTP healthcheck on `/` stays
 * fast and cheap. Use `/health` for a real readiness check.
 */
app.get("/", (_req, res) => res.send("ok"));

/**
 * Probes an upstream backend at `GET /` and resolves with a status
 * descriptor. Never throws — every failure mode is captured as
 * `{ ok: false, ... }` so the caller can serialize it directly.
 */
export function probeBackend(
  service,
  { timeoutMs = HEALTH_CHECK_TIMEOUT_MS, port = INTERNAL_PORT, suffix = INTERNAL_SUFFIX } = {},
) {
  return new Promise((resolve) => {
    const start = Date.now();
    const host = `${service}${suffix}`;
    const req = httpRequest(
      { hostname: host, port, path: "/", method: "GET", timeout: timeoutMs },
      (res) => {
        const ok = res.statusCode !== undefined && res.statusCode < 500;
        res.resume();
        resolve({
          service,
          ok,
          status: res.statusCode,
          latencyMs: Date.now() - start,
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(Object.assign(new Error("timeout"), { code: "UPSTREAM_TIMEOUT" }));
    });
    req.on("error", (err) => {
      resolve({
        service,
        ok: false,
        error: classifyUpstreamError(err),
        errorMessage: err.message,
        latencyMs: Date.now() - start,
      });
    });
    req.end();
  });
}

/**
 * Readiness probe. Verifies:
 *   - SQLite is queryable (`SELECT 1`)
 *   - Each backend in BACKEND_SERVICES responds within HEALTH_CHECK_TIMEOUT_MS
 *
 * Returns 200 with `{ status: "ok", checks: {...} }` when everything is
 * healthy, 503 otherwise. Railway healthchecks can be pointed at this
 * endpoint to restart the gateway when dependencies break.
 */
app.get("/health", async (_req, res) => {
  const checks = {};

  // SQLite check — synchronous and fast. Any failure here means the
  // gateway cannot issue tokens or look up clients.
  const dbStart = Date.now();
  try {
    const row = healthPingStmt.get();
    checks.database = {
      ok: row?.ok === 1,
      latencyMs: Date.now() - dbStart,
    };
  } catch (err) {
    checks.database = {
      ok: false,
      error: err?.message || String(err),
      latencyMs: Date.now() - dbStart,
    };
  }

  // Upstream probes — run in parallel so the overall health response
  // completes in ~max(backend latency) rather than the sum.
  if (BACKEND_SERVICES.length > 0) {
    const results = await Promise.all(
      BACKEND_SERVICES.map((s) => probeBackend(s)),
    );
    checks.backends = {};
    for (const r of results) {
      checks.backends[r.service] = r;
    }
  }

  const allOk =
    checks.database.ok &&
    (!checks.backends ||
      Object.values(checks.backends).every((b) => b.ok));

  res.status(allOk ? 200 : 503).json({
    status: allOk ? "ok" : "degraded",
    checks,
  });
});

// ── Login ───────────────────────────────────────────────────────────────────

const LOGIN_HTML = (redirect, error) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>MCP Gateway — Sign in</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);padding:40px;width:100%;max-width:380px}
    h2{font-size:20px;margin-bottom:4px}
    .sub{color:#666;font-size:14px;margin-bottom:24px}
    label{display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:#333}
    input{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:15px;margin-bottom:16px}
    input:focus{outline:none;border-color:#000;box-shadow:0 0 0 1px #000}
    button{width:100%;padding:12px;background:#000;color:#fff;border:none;border-radius:8px;font-size:15px;cursor:pointer;font-weight:500}
    button:hover{background:#222}
    .err{color:#c00;font-size:13px;margin-bottom:16px}
  </style>
</head>
<body>
  <div class="card">
    <h2>MCP Gateway</h2>
    <p class="sub">Sign in to authorize access to your tools.</p>
    ${error ? '<p class="err">Invalid username or password.</p>' : ""}
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required autofocus />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <input type="hidden" name="redirect" value="${redirect.replace(/"/g, "&quot;")}" />
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`;

app.get("/login", (req, res) => {
  const redirect = req.query.redirect || "/";
  const error = req.query.error === "1";
  res.setHeader("Content-Type", "text/html");
  res.send(LOGIN_HTML(redirect, error));
});

app.post(
  "/login",
  express.urlencoded({ extended: true }),
  async (req, res) => {
    const { username, password, redirect } = req.body;
    if (username === GATEWAY_USERNAME && password === GATEWAY_PASSWORD) {
      const token = await new SignJWT({ sub: username })
        .setProtectedHeader({ alg: "RS256" })
        .setIssuedAt()
        .setExpirationTime("7d")
        .sign(privateKey);
      res.cookie("gateway_session", token, {
        httpOnly: true,
        secure: BASE_URL.startsWith("https"),
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      res.redirect(redirect || "/");
    } else {
      logJson({
        level: "warn",
        msg: "gateway login failed",
        srcIp: req.ip,
        username: typeof username === "string" ? username : null,
        userAgent: req.headers["user-agent"],
      });
      const r = encodeURIComponent(redirect || "/");
      res.redirect(`/login?error=1&redirect=${r}`);
    }
  },
);

// ── RFC 9728 Protected Resource Metadata ────────────────────────────────────
// Registered before @mcpauth/auth so it takes priority for this specific path.

app.get("/.well-known/oauth-protected-resource*", (_req, res) => {
  res.json({
    resource: BASE_URL.replace(/\/$/, ""),
    authorization_servers: [BASE_URL.replace(/\/$/, "")],
    bearer_methods_supported: ["header"],
    scopes_supported: [],
  });
});

// ── @mcpauth/auth OAuth + discovery endpoints ───────────────────────────────
// Body parsing is scoped here so that proxy routes receive raw streams.

app.use(
  "/api/oauth",
  (req, _res, next) => {
    logJson({
      level: "info",
      msg: "oauth request",
      method: req.method,
      path: req.originalUrl,
      srcIp: req.ip,
      userAgent: req.headers["user-agent"],
    });
    next();
  },
  express.json(),
  express.urlencoded({ extended: true }),
  mcpAuth,
);
app.use("/.well-known", mcpAuth);

// ── Service proxy ───────────────────────────────────────────────────────────

/**
 * Validates the Bearer token against the @mcpauth/auth database
 * and proxies authenticated requests to the target backend.
 * No body parsing — the raw request stream is piped through.
 *
 * Paths listed in `PUBLIC_SERVICE_PATHS` bypass Bearer validation — the
 * upstream service is expected to handle those requests safely on its own
 * (e.g. OAuth consent callbacks secured by state/PKCE at the app layer).
 *
 * Every request — authenticated, unauthenticated, proxy errors, 401s —
 * emits a single structured JSON log line on response finish. See the
 * README for the log field contract.
 */
async function validateAndProxy(req, res) {
  const start = Date.now();
  const service = req.params.service;
  const isPublic = isPublicServicePath(service, req.path);
  const mcpSessionId = req.headers["mcp-session-id"] || null;
  const hasBearer = (req.headers.authorization || "")
    .toLowerCase()
    .startsWith("bearer ");
  const userAgent = req.headers["user-agent"];

  // Mutable fields populated during the proxy lifecycle. Captured in the
  // single log line emitted on response finish.
  let userId = null;
  let upstreamStatus = null;
  let upstreamError = null;
  let authReason = null;

  res.on("finish", () => {
    logJson({
      level: upstreamError || res.statusCode >= 500 ? "error" : "info",
      msg: "proxy request",
      srcIp: req.ip,
      method: req.method,
      path: req.originalUrl,
      service,
      public: isPublic,
      hasBearer,
      mcpSessionId,
      userId,
      status: res.statusCode,
      upstreamStatus,
      upstreamError,
      authReason,
      durationMs: Date.now() - start,
      userAgent,
    });
  });

  let session = null;
  if (!isPublic) {
    session = await validateToken(req);
    if (!session) {
      // Run the detailed classifier against our own token store so the
      // audit log distinguishes the four operationally-meaningful cases:
      //   - no-bearer-header  → client is not even trying to auth
      //                         (scanner / misconfigured integration)
      //   - malformed-bearer  → `Bearer<space>` with empty value
      //   - unknown-to-db     → token never issued here, or already
      //                         revoked / DB wiped (credential stuffing,
      //                         stale client, cross-environment leak)
      //   - expired           → token was valid once — this is the
      //                         "Gmail drops out" case: a client that
      //                         failed to refresh in time
      //   - lookup-failed     → DB error during auth — real infra issue
      //   - bad-expiry        → stored expires_at is unparseable
      // NEVER log the token itself — only its 6-char prefix for
      // correlating repeat offenders in the log stream.
      const detail = classify401Detailed(req, {
        lookupToken: lookupTokenForClassifier,
      });
      authReason = detail.reason;
      logJson({
        level: "warn",
        msg: "auth rejected",
        srcIp: req.ip,
        method: req.method,
        path: req.originalUrl,
        service,
        reason: authReason,
        hasBearer: detail.hasBearer,
        tokenPrefix: detail.tokenPrefix,
        userAgent,
      });
      res.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": "Bearer",
      });
      return res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32001, message: "Unauthorized" },
          id: null,
        }),
      );
    }
    // @mcpauth/auth's session shape isn't strictly documented; pull from
    // the commonly-used fields without throwing if any are absent.
    userId = session.user?.id || session.userId || session.sub || null;
  }

  const targetHost = `${service}${INTERNAL_SUFFIX}`;
  const targetPath = req.url || "/";
  const targetUrl = `http://${targetHost}:${INTERNAL_PORT}${targetPath}`;

  const proxyReq = httpRequest(
    {
      hostname: targetHost,
      port: INTERNAL_PORT,
      path: targetPath,
      method: req.method,
      headers: { ...req.headers, host: `${targetHost}:${INTERNAL_PORT}` },
    },
    (proxyRes) => {
      // Forward upstream status + headers verbatim. This is critical for
      // the streamable HTTP MCP transport's session lifecycle: the
      // upstream emits `404 + JSON-RPC -32002 "Session terminated"` when
      // it sees a stale `Mcp-Session-Id` (idle reap or process restart),
      // and the client uses exactly those bytes to drive automatic
      // reinitialize. If the gateway ever rewrote that 404 into a 502
      // the client would get stuck — see the redeploy-recovery test in
      // test/gateway.test.mjs.
      upstreamStatus = proxyRes.statusCode;
      res.writeHead(proxyRes.statusCode, proxyRes.headers);

      // Surface mid-stream errors on the upstream response so they
      // reach the request log instead of being swallowed by `pipe`.
      // We do NOT rewrite the response status here — by the time
      // proxyRes is in flight, headers have been flushed and any
      // attempt to overwrite the status would either no-op or throw.
      // Aborting the response is the truthful behaviour: the client
      // sees a truncated body and treats it as a transport failure,
      // which is what actually happened.
      proxyRes.on("error", (err) => {
        const errorKind = classifyUpstreamError(err);
        upstreamError = upstreamError || errorKind;
        logJson({
          level: "error",
          msg: "upstream response error",
          service,
          targetUrl,
          errorKind,
          errorCode: err.code || null,
          errorMessage: err.message,
        });
        try {
          res.destroy(err);
        } catch {
          // no-op — response may already be closed.
        }
      });

      proxyRes.pipe(res, { end: true });
    },
  );

  // Explicit socket timeout. Without this, Node's socket can hang
  // forever if the upstream accepts the TCP connection but never
  // responds — which is exactly what caused the 15-minute 502s seen
  // on 17 / 24 April 2026 against gmail-mcp.
  proxyReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    proxyReq.destroy(
      Object.assign(new Error("upstream timeout"), {
        code: "UPSTREAM_TIMEOUT",
      }),
    );
  });

  proxyReq.on("error", (err) => {
    const errorKind = classifyUpstreamError(err);
    upstreamError = errorKind;
    const waitedMs = Date.now() - start;
    logJson({
      level: "error",
      msg: "upstream error",
      service,
      targetUrl,
      errorKind,
      errorCode: err.code || null,
      errorMessage: err.message,
      waitedMs,
      timeoutMs: UPSTREAM_TIMEOUT_MS,
    });
    if (!res.headersSent) {
      // The hot path that keeps clients alive across an upstream
      // redeploy. When the upstream is briefly unreachable AND the
      // client carried an `Mcp-Session-Id`, synthesize the same
      // `404 + -32002 "Session terminated"` body the upstream itself
      // would emit once it comes back up with an empty session map.
      // The MCP client (Claude / Cursor) pattern-matches on -32002
      // and reinitializes automatically. Without this branch the
      // gateway returned 502 + -32000, which clients have no recovery
      // path for — so a 30-second redeploy turned into a permanent
      // dead session until the user manually reconnected.
      //
      // In-memory sessions are an explicit design choice (see README
      // → "Sessions and the -32002 contract"); -32002 forwarding is
      // the reason we get away with it.
      const synthesize = shouldSynthesizeSessionTerminated(
        errorKind,
        mcpSessionId,
      );
      if (synthesize) {
        logJson({
          level: "info",
          msg: "synthesized session-terminated",
          service,
          targetUrl,
          errorKind,
          mcpSessionId,
          waitedMs,
        });
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(buildSessionTerminatedBody(null));
        return;
      }

      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(
        buildUpstreamErrorBody(
          errorKind === "upstream-timeout" || errorKind === "socket-timeout"
            ? "Upstream timeout"
            : "Service unavailable",
        ),
      );
    } else {
      // Headers already flushed — best we can do is abort the response.
      try {
        res.destroy(err);
      } catch {
        // no-op — response may already be closed.
      }
    }
  });

  req.pipe(proxyReq, { end: true });
}

app.use("/:service", validateAndProxy);

// ── Start ───────────────────────────────────────────────────────────────────

// Skip binding when imported by tests — exported `app` is used directly.
if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    logJson({
      level: "info",
      msg: "auth gateway started",
      port: Number(PORT),
      baseUrl: BASE_URL,
      accessTokenLifetimeSec: ACCESS_TOKEN_LIFETIME,
      refreshTokenLifetimeSec: REFRESH_TOKEN_LIFETIME,
      upstreamTimeoutMs: UPSTREAM_TIMEOUT_MS,
      backendServices: BACKEND_SERVICES,
      internalSuffix: INTERNAL_SUFFIX,
      internalPort: INTERNAL_PORT,
    });
  });
}

export { app };
