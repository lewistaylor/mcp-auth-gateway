/**
 * Small pure helpers used by the gateway's observability layer.
 *
 * Extracted from server.mjs so they can be unit-tested in isolation
 * — importing server.mjs triggers env-var validation and database
 * bootstrap, which we want to avoid in focused unit tests.
 */

/**
 * Emits a single-line JSON log to stdout. Railway scrapes stdout as-is,
 * so JSON lines are directly queryable in the Railway logs UI.
 *
 * Always prepends an ISO-8601 `ts` field. Callers supply the rest of
 * the log record — typically `level`, `msg`, and any per-request
 * metadata fields (srcIp, path, service, etc.).
 *
 * NEVER pass secrets, tokens, cookies, request bodies, or response
 * bodies into this function — only metadata. Gmail / Xero content is
 * considered sensitive.
 *
 * @param {Record<string, unknown>} obj - log fields to serialize
 * @param {(line: string) => void} [writer] - sink for the serialized
 *   line; defaults to `console.log`. Injected primarily for tests.
 */
export function logJson(obj, writer = console.log) {
  try {
    writer(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
  } catch {
    // JSON.stringify can throw on circular refs. Fall back to a
    // best-effort string dump rather than losing the log line.
    writer(
      JSON.stringify({
        ts: new Date().toISOString(),
        level: "error",
        msg: "log serialization failed",
      }),
    );
  }
}

/**
 * Classifies an upstream network error into a small, stable set of
 * human-readable categories. Operators can then filter Railway logs
 * by e.g. `errorKind:"socket-timeout"` to answer "how many of today's
 * 502s were timeouts vs connection refusals?" without having to parse
 * libuv errno codes.
 *
 * @param {unknown} err - an `Error` produced by `node:http`'s request,
 *   `node:net`, or DNS resolution. `null` / undefined is tolerated.
 * @returns {string} one of:
 *   - "socket-timeout"    — Node's underlying socket timed out
 *   - "upstream-timeout"  — our own setTimeout handler fired
 *   - "connection-refused"— upstream returned RST / was not listening
 *   - "connection-reset"  — peer closed the connection mid-flight
 *   - "host-unreachable"  — routing layer rejected the packet
 *   - "dns-failure"       — resolver could not look up the hostname
 *   - "unknown"           — anything else (or missing err)
 *   - raw `err.code`      — fallback when a code is present but not
 *                           in the allowlist above
 */
export function classifyUpstreamError(err) {
  if (!err) return "unknown";
  if (err.code === "ETIMEDOUT" || err.code === "ESOCKETTIMEDOUT") {
    return "socket-timeout";
  }
  if (err.code === "UPSTREAM_TIMEOUT") return "upstream-timeout";
  if (err.code === "ECONNREFUSED") return "connection-refused";
  if (err.code === "ECONNRESET") return "connection-reset";
  if (err.code === "EHOSTUNREACH") return "host-unreachable";
  if (err.code === "ENOTFOUND" || err.code === "EAI_AGAIN") return "dns-failure";
  return err.code || "unknown";
}

/**
 * Classifies a Bearer-auth rejection into a bounded set of reasons so
 * that repeated failure patterns (credential stuffing, scanner traffic,
 * an expired token a client forgot to refresh) can be grouped.
 *
 * `@mcpauth/auth`'s session validator collapses expired and malformed
 * tokens into a null return, so we cannot distinguish those two — they
 * share the `invalid-or-expired-token` reason.
 *
 * @param {{ headers?: Record<string, string | string[] | undefined> }} req
 * @returns {"no-bearer-header" | "invalid-or-expired-token"}
 */
export function classify401(req) {
  const rawHeader = req?.headers?.authorization;
  const header = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader || "";
  if (!header.toLowerCase().startsWith("bearer ")) return "no-bearer-header";
  return "invalid-or-expired-token";
}
