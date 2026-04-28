/**
 * Tiny JSON-RPC 2.0 helpers used by the gateway's proxy layer.
 *
 * Extracted from server.mjs so the contract — what error codes the
 * gateway emits and when — is unit-testable without booting the full
 * gateway (which requires env vars + SQLite).
 *
 * Two error codes matter for the streamable HTTP MCP transport:
 *
 *   `-32002` "Session terminated" — the only signal that drives an
 *     MCP client (Claude / Cursor) to drop its current session id and
 *     reinitialize. Upstream MCP backends emit this naturally when
 *     they receive a request carrying an `Mcp-Session-Id` they no
 *     longer hold (idle reap, process restart). The gateway also
 *     synthesizes it during the brief window where an upstream is
 *     unreachable due to a Railway redeploy — see
 *     `shouldSynthesizeSessionTerminated` for the exact rules.
 *
 *   `-32000` "Service unavailable" / "Upstream timeout" — generic
 *     upstream failure that the client cannot recover from on its
 *     own. Used when there is no session id, so synthesizing -32002
 *     would lie ("you have no session to terminate") and would also
 *     not actually help the client recover.
 */

/** JSON-RPC error code: stale / terminated session. Drives client reinit. */
export const JSONRPC_SESSION_TERMINATED = -32002;

/** JSON-RPC error code: generic server/upstream failure. */
export const JSONRPC_INTERNAL_ERROR = -32000;

/**
 * The set of upstream connection failure modes for which it is safe —
 * and beneficial — to synthesize a `-32002 "Session terminated"`
 * response when the request carried an `Mcp-Session-Id`.
 *
 * The reasoning, kind by kind:
 *
 *   - `connection-refused` / `connection-reset` / `host-unreachable`
 *     `dns-failure` (a Railway internal DNS hiccup during deploy)
 *     `socket-timeout` / `upstream-timeout`
 *
 *   These are exactly the failure modes that show up during a Railway
 *   redeploy of an upstream MCP backend (the upstream is being torn
 *   down or hasn't yet started listening). Once the redeploy lands,
 *   the upstream comes back with an empty session map and would itself
 *   return `404 + -32002` for the same request — so we just bring that
 *   forward by a few seconds. The net effect is that the client
 *   reinitializes once and recovers, instead of seeing a 502 it
 *   doesn't know how to handle.
 *
 * If a kind is not in this set we fall through to the generic 502 +
 * -32000 path. Any kind appearing here that does NOT in fact correlate
 * with "upstream restarted, session is gone" risks lying to clients,
 * so add new entries deliberately.
 */
export const RECOVERABLE_UPSTREAM_ERRORS = new Set([
  "connection-refused",
  "connection-reset",
  "host-unreachable",
  "dns-failure",
  "socket-timeout",
  "upstream-timeout",
]);

/**
 * Returns true when an upstream connection failure should be presented
 * to the client as `404 + -32002 "Session terminated"` rather than
 * `502 + -32000 "Service unavailable"`.
 *
 * Rules:
 *   1. The request must carry an `Mcp-Session-Id` — otherwise the
 *      client has no session to "terminate" and would be misled.
 *   2. The classified upstream error kind must be in
 *      `RECOVERABLE_UPSTREAM_ERRORS` — otherwise the failure is
 *      probably not a redeploy and the truthful 502 is better.
 *
 * @param {string | null | undefined} errorKind
 *   The output of `classifyUpstreamError(err)` from observability.mjs.
 * @param {string | null | undefined} mcpSessionId
 *   The value of the request's `Mcp-Session-Id` header.
 * @returns {boolean}
 */
export function shouldSynthesizeSessionTerminated(errorKind, mcpSessionId) {
  if (!mcpSessionId) return false;
  if (typeof errorKind !== "string") return false;
  return RECOVERABLE_UPSTREAM_ERRORS.has(errorKind);
}

/**
 * Builds the JSON body returned to a client whose session is gone.
 *
 * Mirrors the shape used by the upstream MCP backends
 * (see e.g. notion-mcp/src/transport.ts → `buildSessionTerminatedBody`)
 * so that whether the 404 came from upstream verbatim or was
 * synthesized by the gateway, the client sees the exact same bytes
 * and recovers via the same code path.
 *
 * @param {string | number | null} [id=null]
 *   JSON-RPC request id, if known. The gateway streams the request
 *   body straight through to the upstream so it usually does NOT
 *   parse it, in which case `null` is the correct value (and is
 *   permitted by the JSON-RPC 2.0 spec for error responses where the
 *   id couldn't be determined).
 * @returns {string} JSON-encoded body, ready to write to the response.
 */
export function buildSessionTerminatedBody(id = null) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id,
    error: {
      code: JSONRPC_SESSION_TERMINATED,
      message: "Session terminated",
    },
  });
}

/**
 * Builds the JSON body returned for a generic upstream failure that
 * the client cannot recover from automatically.
 *
 * @param {string} message
 *   Human-readable error string. Should not contain secrets — this
 *   is sent verbatim to the client.
 * @param {string | number | null} [id=null]
 * @returns {string} JSON-encoded body, ready to write to the response.
 */
export function buildUpstreamErrorBody(message, id = null) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id,
    error: {
      code: JSONRPC_INTERNAL_ERROR,
      message,
    },
  });
}
