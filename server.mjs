#!/usr/bin/env node

/**
 * OAuth 2.1 auth gateway for MCP servers.
 *
 * Sits in front of one or more MCP backend services on Railway private
 * networking. Validates JWT access tokens issued by Auth0 (or any OIDC
 * provider), serves RFC 9728 Protected Resource Metadata so clients
 * can discover the authorization server, and proxies authenticated
 * requests to the appropriate backend.
 *
 * Route convention:
 *   /<service>/...  →  <service>-mcp.railway.internal:<INTERNAL_PORT>/...
 *
 * Health check (GET / or /health) bypasses auth for Railway.
 */

import express from "express";
import { MCPAuth, fetchServerConfig } from "mcp-auth";
import { request as httpRequest } from "node:http";

// ── Config ──────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || "8000";
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;
const INTERNAL_SUFFIX =
  process.env.INTERNAL_SUFFIX || "-mcp.railway.internal";
const INTERNAL_PORT = parseInt(process.env.INTERNAL_PORT || "8000", 10);

if (!AUTH0_DOMAIN || !AUTH0_AUDIENCE) {
  console.error(
    "[auth-gateway] Fatal: AUTH0_DOMAIN and AUTH0_AUDIENCE are required",
  );
  process.exit(1);
}

// ── MCP Auth init ───────────────────────────────────────────────────────────

const issuerUrl = `https://${AUTH0_DOMAIN}/`;

console.log(`[auth-gateway] Fetching OIDC config from ${issuerUrl}...`);
const authServerConfig = await fetchServerConfig(issuerUrl, { type: "oidc" });

const mcpAuth = new MCPAuth({
  protectedResources: {
    metadata: {
      resource: AUTH0_AUDIENCE,
      authorizationServers: [authServerConfig],
      scopesSupported: [],
    },
  },
});

const bearerAuth = mcpAuth.bearerAuth("jwt", {
  resource: AUTH0_AUDIENCE,
  audience: AUTH0_AUDIENCE,
});

// ── Express app ─────────────────────────────────────────────────────────────

const app = express();

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

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

app.get("/", (_req, res) => res.send("ok"));
app.get("/health", (_req, res) => res.send("ok"));

app.use(mcpAuth.protectedResourceMetadataRouter());

// ── Service proxy ───────────────────────────────────────────────────────────

/**
 * Pipes an authenticated request to the target backend service.
 * Handles streaming responses (SSE) transparently.
 *
 * @param {string}                      service  Service name (e.g. "xero")
 * @param {import("http").IncomingMessage} req   Incoming Express request
 * @param {import("http").ServerResponse}  res   Outgoing Express response
 */
function proxyToService(service, req, res) {
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

app.use("/:service", bearerAuth, (req, res) => {
  proxyToService(req.params.service, req, res);
});

// ── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[auth-gateway] Listening on port ${PORT}`);
  console.log(`[auth-gateway] Auth0 domain: ${AUTH0_DOMAIN}`);
  console.log(`[auth-gateway] Audience: ${AUTH0_AUDIENCE}`);
  console.log(
    `[auth-gateway] Proxying /<service>/... → <service>${INTERNAL_SUFFIX}:${INTERNAL_PORT}/...`,
  );
});

export { app, proxyToService };
