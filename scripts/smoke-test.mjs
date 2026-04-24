#!/usr/bin/env node

/**
 * Minimal end-to-end smoke test for the auth gateway.
 *
 * Given a Bearer access token, drives a representative sequence of
 * calls against a deployed gateway and reports per-step latency and
 * status. Intended for:
 *
 *   - post-deploy sanity checks (e.g. after Railway deploys)
 *   - diagnosing the "400 after OAuth reconnect" failure mode by
 *     exercising a fresh MCP initialize → tools/list handshake
 *   - comparing upstream latency over time
 *
 * Usage:
 *
 *   BASE_URL=https://auth-gateway-production-c510.up.railway.app \
 *   BEARER_TOKEN=<paste access token> \
 *   SERVICE=gmail-work \
 *   npm run smoke
 *
 * The script exits 0 when every step reports a non-5xx status AND the
 * initialize handshake returns a server-generated `Mcp-Session-Id`.
 * Any other outcome exits non-zero so CI / cron can alert on it.
 *
 * Security: the Bearer token is read from BEARER_TOKEN and is NEVER
 * logged. Response bodies are truncated to 500 chars so accidental
 * leakage of Gmail content into logs is bounded.
 */

const BASE_URL =
  process.env.BASE_URL || "https://auth-gateway-production-c510.up.railway.app";
const BEARER_TOKEN = process.env.BEARER_TOKEN;
const SERVICE = process.env.SERVICE || "gmail-work";

const MAX_BODY_CHARS = 500;

if (!BEARER_TOKEN) {
  console.error(
    "error: BEARER_TOKEN is required. Obtain one by completing the OAuth flow " +
      "against the gateway and pasting the access_token from POST /api/oauth/token.",
  );
  process.exit(2);
}

/**
 * Wraps `fetch` with a per-step timing harness. Returns an object with
 * status, latency in milliseconds, a truncated response body, and the
 * session id header (if the server set one).
 */
async function timed(label, url, init = {}) {
  const start = Date.now();
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    const latencyMs = Date.now() - start;
    return {
      label,
      ok: false,
      status: 0,
      latencyMs,
      error: err?.message || String(err),
    };
  }
  const text = await res.text();
  const latencyMs = Date.now() - start;
  return {
    label,
    ok: res.status < 500,
    status: res.status,
    latencyMs,
    sessionId: res.headers.get("mcp-session-id"),
    body:
      text.length > MAX_BODY_CHARS ? text.slice(0, MAX_BODY_CHARS) + "…" : text,
  };
}

/**
 * Summarizes a step result to stdout. Body is only printed when the
 * step failed or when SMOKE_VERBOSE=1 so we don't spam logs on
 * success.
 */
function report(step) {
  const badge = step.ok ? "OK " : "FAIL";
  const extra = step.sessionId ? ` sid=${step.sessionId}` : "";
  console.log(
    `[${badge}] ${step.label.padEnd(28)} ` +
      `status=${String(step.status).padEnd(3)} ` +
      `latency=${String(step.latencyMs).padStart(5)}ms${extra}`,
  );
  if (!step.ok || process.env.SMOKE_VERBOSE === "1") {
    if (step.error) console.log(`       error: ${step.error}`);
    if (step.body) console.log(`       body:  ${step.body}`);
  }
}

async function main() {
  console.log(
    `smoke-test against ${BASE_URL} (service=${SERVICE})\n` +
      `─────────────────────────────────────────────────────────────`,
  );

  const results = [];

  // 1. Health probe — no auth required.
  results.push(await timed("GET /health", `${BASE_URL}/health`));

  // 2. initialize — sends the MCP handshake without a session id so the
  //    server allocates one. A fresh session id in the response header
  //    is the signal that the upstream transport accepted the client.
  const initRes = await timed(
    `POST /${SERVICE}/mcp initialize`,
    `${BASE_URL}/${SERVICE}/mcp`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${BEARER_TOKEN}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "mcp-auth-gateway-smoke", version: "0.1.0" },
        },
      }),
    },
  );
  results.push(initRes);

  // 3. tools/list — reuses the session id from the initialize response,
  //    which is what a real MCP client does. If the upstream restarted
  //    between steps 2 and 3, we expect the server to reject step 3;
  //    that's exactly the failure mode documented in the gmail-mcp
  //    "400 after reconnect" issue.
  const sessionId = initRes.sessionId;
  if (sessionId) {
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${BEARER_TOKEN}`,
      "Mcp-Session-Id": sessionId,
    };
    results.push(
      await timed(
        `POST /${SERVICE}/mcp tools/list`,
        `${BASE_URL}/${SERVICE}/mcp`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 2,
            method: "tools/list",
            params: {},
          }),
        },
      ),
    );
  } else {
    results.push({
      label: `POST /${SERVICE}/mcp tools/list`,
      ok: false,
      status: 0,
      latencyMs: 0,
      error: "skipped — initialize did not return an Mcp-Session-Id header",
    });
  }

  console.log("");
  for (const step of results) report(step);

  const failed = results.filter((r) => !r.ok);
  console.log(
    `─────────────────────────────────────────────────────────────\n` +
      `${results.length - failed.length}/${results.length} steps passed`,
  );
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("smoke-test: unexpected error", err);
  process.exit(2);
});
