import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import http from "node:http";

/**
 * Integration tests for the auth gateway.
 *
 * These tests spin up a minimal Express app that mirrors the gateway's
 * middleware stack but uses a stub auth provider instead of Auth0.
 * A fake backend MCP service is also started so proxy behaviour can
 * be verified end-to-end.
 */

const FAKE_BACKEND_PORT = 19876;
const GATEWAY_PORT = 19877;
const VALID_TOKEN = "test-valid-token";

/**
 * Mirrors the real server.mjs PUBLIC_SERVICE_PATHS env var — lists
 * `<service>:<path>` pairs that bypass Bearer validation. Kept as a
 * constant in tests so the behaviour can be asserted without spinning
 * up a full Railway environment.
 */
const PUBLIC_SERVICE_PATHS = new Set([
  "gmail:/oauth2callback",
  "gmail:/auth/start",
]);

let fakeBackend;
let gateway;

/**
 * Starts a tiny HTTP server that pretends to be an internal MCP service.
 * Returns "ok" for GET / and echoes request details for everything else.
 */
function startFakeBackend() {
  return new Promise((resolve) => {
    fakeBackend = http.createServer((req, res) => {
      if (req.method === "GET" && req.url === "/") {
        res.writeHead(200);
        res.end("ok");
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      const body = JSON.stringify({
        method: req.method,
        url: req.url,
        proxied: true,
      });
      res.end(body);
    });
    fakeBackend.listen(FAKE_BACKEND_PORT, resolve);
  });
}

/**
 * Starts an Express app with a stub bearer auth middleware that accepts
 * a hardcoded token and rejects everything else with 401.
 */
function startGateway() {
  return new Promise((resolve) => {
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
      if (req.method === "OPTIONS") return res.sendStatus(204);
      next();
    });

    app.get("/", (_req, res) => res.send("ok"));
    app.get("/health", (_req, res) => res.send("ok"));

    const stubAuth = (req, res, next) => {
      const service = req.params.service;
      if (PUBLIC_SERVICE_PATHS.has(`${service}:${req.path}`)) {
        return next();
      }
      const authHeader = req.headers.authorization || "";
      if (authHeader !== `Bearer ${VALID_TOKEN}`) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32001, message: "Unauthorized" },
            id: null,
          }),
        );
      }
      next();
    };

    app.use("/:service", stubAuth, (req, res) => {
      const proxyReq = http.request(
        {
          hostname: "127.0.0.1",
          port: FAKE_BACKEND_PORT,
          path: req.url || "/",
          method: req.method,
          headers: req.headers,
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res, { end: true });
        },
      );
      proxyReq.on("error", (err) => {
        if (!res.headersSent) {
          res.writeHead(502);
          res.end(`Proxy error: ${err.message}`);
        }
      });
      req.pipe(proxyReq, { end: true });
    });

    gateway = app.listen(GATEWAY_PORT, resolve);
  });
}

function fetch(path, opts = {}) {
  return globalThis.fetch(`http://127.0.0.1:${GATEWAY_PORT}${path}`, opts);
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("auth gateway", () => {
  before(async () => {
    await startFakeBackend();
    await startGateway();
  });

  after(() => {
    gateway?.close();
    fakeBackend?.close();
  });

  it("GET / returns 200 without auth", async () => {
    const res = await fetch("/");
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "ok");
  });

  it("GET /health returns 200 without auth", async () => {
    const res = await fetch("/health");
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "ok");
  });

  it("OPTIONS returns 204 (CORS preflight)", async () => {
    const res = await fetch("/xero/mcp", { method: "OPTIONS" });
    assert.equal(res.status, 204);
  });

  it("rejects unauthenticated service requests with 401", async () => {
    const res = await fetch("/xero/mcp", { method: "POST" });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error.code, -32001);
  });

  it("rejects wrong token with 401", async () => {
    const res = await fetch("/xero/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer wrong-token" },
    });
    assert.equal(res.status, 401);
  });

  it("proxies authenticated requests to backend", async () => {
    const res = await fetch("/xero/mcp", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${VALID_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ test: true }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.proxied, true);
    assert.equal(body.method, "POST");
    assert.equal(body.url, "/mcp");
  });

  it("strips service prefix when proxying", async () => {
    const res = await fetch("/clockify/sse", {
      headers: { Authorization: `Bearer ${VALID_TOKEN}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.url, "/sse");
  });

  it("CORS headers are present on responses", async () => {
    const res = await fetch("/health");
    assert.equal(res.headers.get("access-control-allow-origin"), "*");
  });

  // ── Public service paths ───────────────────────────────────────────────

  it("allows unauthenticated access to configured public service paths", async () => {
    const res = await fetch("/gmail/oauth2callback?code=abc&state=xyz");
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.proxied, true);
    assert.equal(body.url, "/oauth2callback?code=abc&state=xyz");
  });

  it("proxies /auth/start without Bearer token when listed in PUBLIC_SERVICE_PATHS", async () => {
    const res = await fetch("/gmail/auth/start?setup_token=secret");
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.url, "/auth/start?setup_token=secret");
  });

  it("still requires Bearer for non-public paths on services with public paths", async () => {
    const res = await fetch("/gmail/mcp", { method: "POST" });
    assert.equal(res.status, 401);
  });

  it("matches paths exactly — adjacent paths are NOT public", async () => {
    const res = await fetch("/gmail/oauth2callback/extra");
    assert.equal(res.status, 401);
  });

  it("does not leak public-path bypass to other services", async () => {
    const res = await fetch("/xero/oauth2callback");
    assert.equal(res.status, 401);
  });
});
