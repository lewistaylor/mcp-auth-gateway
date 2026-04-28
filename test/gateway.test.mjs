import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import http from "node:http";
import { classifyUpstreamError } from "../lib/observability.mjs";
import {
  shouldSynthesizeSessionTerminated,
  buildSessionTerminatedBody,
  buildUpstreamErrorBody,
} from "../lib/jsonrpc.mjs";

/**
 * Integration tests for the auth gateway.
 *
 * These tests spin up a minimal Express app that mirrors the gateway's
 * middleware stack but uses a stub auth provider instead of Auth0.
 * A fake backend MCP service is also started so proxy behaviour can
 * be verified end-to-end.
 *
 * The proxy harness below imports the SAME lib/jsonrpc.mjs and
 * lib/observability.mjs helpers that server.mjs uses, so the
 * redeploy-recovery contract (`-32002` synthesis, upstream 404
 * passthrough) is exercised against the production code paths rather
 * than a duplicated copy.
 */

const FAKE_BACKEND_PORT = 19876;
const GATEWAY_PORT = 19877;
/** Port that is intentionally NOT listened on so we can simulate ECONNREFUSED. */
const DEAD_BACKEND_PORT = 19878;
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
 *
 * Routes:
 *   - `GET /`              → 200 "ok" (used by the gateway's health probe)
 *   - `POST /mcp/stale`    → 404 + JSON-RPC `-32002 "Session terminated"`
 *                            (mirrors what notion-mcp / gmail-mcp emit
 *                            when a stale Mcp-Session-Id is presented)
 *   - everything else      → 200 + a JSON echo of the request shape
 *
 * The stale-session route is the key passthrough fixture: if the
 * gateway ever rewrites this 404 into a 502 the redeploy-recovery
 * contract is broken.
 */
function startFakeBackend() {
  return new Promise((resolve) => {
    fakeBackend = http.createServer((req, res) => {
      if (req.method === "GET" && req.url === "/") {
        res.writeHead(200);
        res.end("ok");
        return;
      }
      if (req.method === "POST" && req.url === "/mcp/stale") {
        // Match the upstream contract byte-for-byte — see
        // notion-mcp/src/transport.ts → buildSessionTerminatedBody.
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 42,
            error: { code: -32002, message: "Session terminated" },
          }),
        );
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
 * Per-service port map. Most services route to the live fake backend
 * so existing assertions still pass; `down` deliberately routes to a
 * port nothing is listening on so we can simulate the ECONNREFUSED
 * window during a Railway redeploy.
 */
const SERVICE_PORTS = {
  down: DEAD_BACKEND_PORT,
};

/**
 * Starts an Express app whose proxy layer mirrors `validateAndProxy`
 * in server.mjs. Auth is stubbed (we're not testing OAuth here) but
 * the upstream-error → -32002 / -32000 logic uses the real helpers
 * from lib/jsonrpc.mjs and lib/observability.mjs, so a regression in
 * the redeploy-recovery contract trips this test.
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
      const service = req.params.service;
      const targetPort = SERVICE_PORTS[service] ?? FAKE_BACKEND_PORT;
      const mcpSessionId = req.headers["mcp-session-id"] || null;

      const proxyReq = http.request(
        {
          hostname: "127.0.0.1",
          port: targetPort,
          path: req.url || "/",
          method: req.method,
          headers: req.headers,
        },
        (proxyRes) => {
          // Forward upstream status + headers verbatim — required by
          // the streamable HTTP MCP transport so that the upstream's
          // own `404 + -32002` reaches the client unchanged.
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res, { end: true });
        },
      );

      proxyReq.on("error", (err) => {
        if (res.headersSent) {
          try {
            res.destroy(err);
          } catch {
            // no-op
          }
          return;
        }
        const errorKind = classifyUpstreamError(err);
        if (shouldSynthesizeSessionTerminated(errorKind, mcpSessionId)) {
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

  // ── Upstream 404 passthrough (the -32002 contract) ─────────────────────
  //
  // The streamable HTTP MCP transport uses `404 + JSON-RPC -32002
  // "Session terminated"` as its sole signal for "your session is
  // gone, please reinitialize". If the gateway ever rewrites that
  // upstream 404 into anything else, MCP clients (Claude / Cursor)
  // get stuck — they have no recovery path for a 502, and they will
  // not auto-retry on a 404 that lacks the -32002 body. So the next
  // three tests pin every byte of that path.

  it("forwards upstream 404 status verbatim", async () => {
    const res = await fetch("/xero/mcp/stale", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${VALID_TOKEN}`,
        "Content-Type": "application/json",
        "Mcp-Session-Id": "stale-session-id-from-before-restart",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 42, method: "tools/list" }),
    });
    assert.equal(res.status, 404);
  });

  it("forwards upstream -32002 body verbatim", async () => {
    const res = await fetch("/xero/mcp/stale", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${VALID_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 42, method: "tools/list" }),
    });
    const body = await res.json();
    assert.equal(body.jsonrpc, "2.0");
    assert.equal(body.error.code, -32002);
    assert.equal(body.error.message, "Session terminated");
    // The upstream supplied id=42; the gateway must not strip or
    // rewrite it. The MCP client correlates errors with requests via
    // this id, so dropping it would break tool-call error reporting.
    assert.equal(body.id, 42);
  });

  it("preserves upstream Content-Type on a 404 -32002", async () => {
    const res = await fetch("/xero/mcp/stale", {
      method: "POST",
      headers: { Authorization: `Bearer ${VALID_TOKEN}` },
    });
    assert.match(
      res.headers.get("content-type") || "",
      /application\/json/,
    );
  });

  // ── Redeploy-recovery synthesis ────────────────────────────────────────
  //
  // During the brief window between Railway tearing down the old
  // upstream container and the new one binding the port, the gateway
  // sees ECONNREFUSED. Without the synthesis path it returns 502 +
  // -32000, which clients can't recover from — so a 30-second
  // redeploy turns into a permanent dead session until the user
  // manually reconnects. With it, the client sees the same -32002
  // it would have seen had the upstream finished restarting first
  // (in-memory sessions are wiped on every redeploy), and reinits.

  it(
    "synthesizes 404 + -32002 when upstream is unreachable AND a session id is carried",
    async () => {
      const res = await fetch("/down/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${VALID_TOKEN}`,
          "Content-Type": "application/json",
          "Mcp-Session-Id": "some-session-from-before-redeploy",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 7,
          method: "tools/list",
        }),
      });
      assert.equal(res.status, 404);
      const body = await res.json();
      assert.equal(body.error.code, -32002);
      assert.equal(body.error.message, "Session terminated");
    },
  );

  it(
    "returns 502 + -32000 when upstream is unreachable and NO session id is carried",
    async () => {
      // No session id implies the client is doing `initialize`;
      // synthesizing -32002 there would be a lie ("you had no
      // session to terminate") and would not help recovery.
      const res = await fetch("/down/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${VALID_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
        }),
      });
      assert.equal(res.status, 502);
      const body = await res.json();
      assert.equal(body.error.code, -32000);
    },
  );
});
