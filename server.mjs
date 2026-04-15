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
 *   GET  /                                → health check
 *   GET  /health                          → health check
 *   GET  /login                           → login page
 *   POST /login                           → login handler
 *        /api/oauth/*                     → @mcpauth/auth OAuth endpoints
 *        /.well-known/*                   → @mcpauth/auth + RFC 9728 metadata
 *        /<service>/*                     → token-validated proxy to backends
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

// ── Config ──────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || "8000";
const BASE_URL = process.env.BASE_URL;
const GATEWAY_USERNAME = process.env.GATEWAY_USERNAME;
const GATEWAY_PASSWORD = process.env.GATEWAY_PASSWORD;
const DATABASE_PATH = process.env.DATABASE_PATH || "./data/db.sqlite";
const INTERNAL_SUFFIX =
  process.env.INTERNAL_SUFFIX || "-mcp.railway.internal";
const INTERNAL_PORT = parseInt(process.env.INTERNAL_PORT || "8000", 10);

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

mkdirSync(dirname(DATABASE_PATH), { recursive: true });

import Database from "better-sqlite3";

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

const mcpAuthConfig = {
  adapter: SqliteAdapter(DATABASE_PATH),
  issuerUrl: BASE_URL,
  issuerPath: "/api/oauth",
  serverOptions: {
    accessTokenLifetime: 3600,
    refreshTokenLifetime: 1209600,
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

app.get("/", (_req, res) => res.send("ok"));
app.get("/health", (_req, res) => res.send("ok"));

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
 */
async function validateAndProxy(req, res) {
  const session = await validateToken(req);
  if (!session) {
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

  const service = req.params.service;
  const targetHost = `${service}${INTERNAL_SUFFIX}`;
  const targetPath = req.url || "/";

  const proxyReq = httpRequest(
    {
      hostname: targetHost,
      port: INTERNAL_PORT,
      path: targetPath,
      method: req.method,
      headers: { ...req.headers, host: `${targetHost}:${INTERNAL_PORT}` },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res, { end: true });
    },
  );

  proxyReq.on("error", (err) => {
    console.error(`[proxy] ${service}: ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Service unavailable" },
          id: null,
        }),
      );
    }
  });

  req.pipe(proxyReq, { end: true });
}

app.use("/:service", validateAndProxy);

// ── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[auth-gateway] Listening on port ${PORT}`);
  console.log(`[auth-gateway] Base URL: ${BASE_URL}`);
  console.log(`[auth-gateway] OAuth: ${BASE_URL}/api/oauth/`);
  console.log(
    `[auth-gateway] Proxying /<service>/... → <service>${INTERNAL_SUFFIX}:${INTERNAL_PORT}/...`,
  );
});

export { app };
