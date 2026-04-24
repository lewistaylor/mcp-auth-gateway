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
 * Extracts the Bearer token from a request's `Authorization` header.
 * Returns `null` when the header is absent or doesn't use the Bearer
 * scheme. The returned token string may still be empty — check length
 * at the call site before using it.
 *
 * @param {{ headers?: Record<string, string | string[] | undefined> }} req
 * @returns {string | null}
 */
export function extractBearerToken(req) {
  const rawHeader = req?.headers?.authorization;
  const header = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader || "";
  if (!header) return null;
  const match = /^bearer\s+(.*)$/i.exec(header);
  if (!match) return null;
  return match[1].trim();
}

/**
 * Coarse syntactic classification of a Bearer-auth rejection, used
 * when we have no database access (e.g. pure unit tests). For the
 * full DB-aware classifier use {@link classify401Detailed}.
 *
 * @param {{ headers?: Record<string, string | string[] | undefined> }} req
 * @returns {"no-bearer-header" | "malformed-bearer" | "invalid-or-expired-token"}
 */
export function classify401(req) {
  const rawHeader = req?.headers?.authorization;
  const header = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader || "";
  if (!header.toLowerCase().startsWith("bearer ")) return "no-bearer-header";
  const token = extractBearerToken(req);
  if (!token) return "malformed-bearer";
  return "invalid-or-expired-token";
}

/**
 * Full classification of why a Bearer request was rejected. Uses a
 * caller-supplied `lookupToken` function (which typically hits the
 * `oauth_token` table) so the classifier stays pure and testable.
 *
 * The returned reason is one of:
 *
 *   - `no-bearer-header`       — no `Authorization` header, or not Bearer
 *   - `malformed-bearer`       — `Bearer` scheme with empty / whitespace value
 *   - `unknown-to-db`          — token not found in the token store
 *     (revoked, wrong issuer, or scanner-style garbage)
 *   - `expired`                — token exists but `expires_at` is in the past
 *   - `valid`                  — token is present and live (the caller
 *     should NOT be emitting a 401 in this case; returned only as a
 *     sanity value for tests)
 *
 * `lookupToken(token)` must synchronously return:
 *   - `null` / `undefined` if the token is unknown
 *   - `{ expiresAt: Date | string | number }` if known (any value
 *     parseable by `new Date()` is accepted, matching SQLite TEXT
 *     timestamps, epoch seconds, or JS `Date` objects)
 *
 * @param {{ headers?: Record<string, string | string[] | undefined> }} req
 * @param {{ lookupToken: (token: string) => { expiresAt: Date | string | number } | null | undefined, now?: Date }} deps
 * @returns {{ reason: string, hasBearer: boolean, tokenPrefix: string | null }}
 *   `tokenPrefix` is the first 6 chars of the token (for log correlation
 *   only) — NEVER the full token.
 */
export function classify401Detailed(req, { lookupToken, now = new Date() }) {
  const rawHeader = req?.headers?.authorization;
  const header = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader || "";
  if (!header.toLowerCase().startsWith("bearer ")) {
    return { reason: "no-bearer-header", hasBearer: false, tokenPrefix: null };
  }
  const token = extractBearerToken(req);
  if (!token) {
    return { reason: "malformed-bearer", hasBearer: true, tokenPrefix: null };
  }
  const tokenPrefix = token.slice(0, 6);

  let row;
  try {
    row = lookupToken(token);
  } catch {
    // A DB-level failure during auth should not be reported as
    // "unknown token" — that would be misleading and would hide real
    // infra problems. Surface it as a distinct category so ops can
    // alert on it.
    return { reason: "lookup-failed", hasBearer: true, tokenPrefix };
  }

  if (!row) {
    return { reason: "unknown-to-db", hasBearer: true, tokenPrefix };
  }

  const expiresAt = new Date(row.expiresAt);
  if (isNaN(expiresAt.getTime())) {
    // Defensive: the DB shouldn't contain a bad timestamp, but if it
    // does we want the log line to say so rather than silently
    // treating it as "valid".
    return { reason: "bad-expiry", hasBearer: true, tokenPrefix };
  }
  if (expiresAt.getTime() <= now.getTime()) {
    return { reason: "expired", hasBearer: true, tokenPrefix };
  }
  return { reason: "valid", hasBearer: true, tokenPrefix };
}
