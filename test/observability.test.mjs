import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  logJson,
  classifyUpstreamError,
  classify401,
  classify401Detailed,
  extractBearerToken,
} from "../lib/observability.mjs";

/**
 * Unit tests for the pure observability helpers.
 *
 * These run without touching the database or requiring env vars,
 * which lets us assert the log field contract and the error-classification
 * rules — the things operators will most depend on when grepping Railway
 * logs during an incident.
 */

describe("logJson", () => {
  it("emits a single line with an ISO timestamp prefix", () => {
    const lines = [];
    logJson({ level: "info", msg: "hi" }, (l) => lines.push(l));
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]);
    assert.equal(typeof parsed.ts, "string");
    assert.match(parsed.ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    assert.equal(parsed.level, "info");
    assert.equal(parsed.msg, "hi");
  });

  it("preserves caller-supplied fields verbatim", () => {
    const lines = [];
    logJson(
      { srcIp: "1.2.3.4", status: 401, durationMs: 7 },
      (l) => lines.push(l),
    );
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.srcIp, "1.2.3.4");
    assert.equal(parsed.status, 401);
    assert.equal(parsed.durationMs, 7);
  });

  it("never throws when given a circular structure", () => {
    const lines = [];
    const circular = { level: "info" };
    circular.self = circular;
    assert.doesNotThrow(() => logJson(circular, (l) => lines.push(l)));
    // A best-effort fallback line is emitted so operators still see
    // *something* rather than silently dropping the log.
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.level, "error");
    assert.equal(parsed.msg, "log serialization failed");
  });
});

describe("classifyUpstreamError", () => {
  const cases = [
    [{ code: "ETIMEDOUT" }, "socket-timeout"],
    [{ code: "ESOCKETTIMEDOUT" }, "socket-timeout"],
    [{ code: "UPSTREAM_TIMEOUT" }, "upstream-timeout"],
    [{ code: "ECONNREFUSED" }, "connection-refused"],
    [{ code: "ECONNRESET" }, "connection-reset"],
    [{ code: "EHOSTUNREACH" }, "host-unreachable"],
    [{ code: "ENOTFOUND" }, "dns-failure"],
    [{ code: "EAI_AGAIN" }, "dns-failure"],
    [{ code: "EPIPE" }, "EPIPE"],
    [{}, "unknown"],
    [null, "unknown"],
    [undefined, "unknown"],
  ];

  for (const [err, expected] of cases) {
    it(`maps ${err?.code ?? "null/undefined"} → ${expected}`, () => {
      assert.equal(classifyUpstreamError(err), expected);
    });
  }
});

describe("extractBearerToken", () => {
  it("returns null when no Authorization header is present", () => {
    assert.equal(extractBearerToken({ headers: {} }), null);
  });

  it("returns null for non-Bearer schemes", () => {
    assert.equal(
      extractBearerToken({ headers: { authorization: "Basic aGVsbG86Zm9v" } }),
      null,
    );
  });

  it("extracts the token body verbatim", () => {
    assert.equal(
      extractBearerToken({ headers: { authorization: "Bearer abc.def-ghi" } }),
      "abc.def-ghi",
    );
  });

  it("trims surrounding whitespace from the token body", () => {
    assert.equal(
      extractBearerToken({ headers: { authorization: "Bearer   abc   " } }),
      "abc",
    );
  });
});

describe("classify401 (syntactic)", () => {
  it("returns no-bearer-header when Authorization is absent", () => {
    assert.equal(classify401({ headers: {} }), "no-bearer-header");
  });

  it("returns no-bearer-header when auth scheme is not Bearer", () => {
    assert.equal(
      classify401({ headers: { authorization: "Basic aGVsbG86Zm9v" } }),
      "no-bearer-header",
    );
  });

  it("is case-insensitive on the Bearer scheme token", () => {
    assert.equal(
      classify401({ headers: { authorization: "bearer deadbeef" } }),
      "invalid-or-expired-token",
    );
  });

  it("returns malformed-bearer when the value is blank", () => {
    assert.equal(
      classify401({ headers: { authorization: "Bearer    " } }),
      "malformed-bearer",
    );
  });

  it("returns invalid-or-expired-token when a Bearer token is present", () => {
    assert.equal(
      classify401({ headers: { authorization: "Bearer abc" } }),
      "invalid-or-expired-token",
    );
  });

  it("tolerates missing headers object entirely", () => {
    assert.equal(classify401({}), "no-bearer-header");
    assert.equal(classify401(undefined), "no-bearer-header");
  });
});

describe("classify401Detailed (DB-aware)", () => {
  /** Fixed "now" so the expired/valid split is deterministic. */
  const NOW = new Date("2026-04-24T10:00:00Z");
  const future = new Date("2026-04-24T11:00:00Z");
  const past = new Date("2026-04-24T09:00:00Z");

  /** Builds a `lookupToken` spy backed by an in-memory map. */
  function makeLookup(entries) {
    const map = new Map(Object.entries(entries));
    return (token) => map.get(token) || null;
  }

  it("classifies absent Authorization as no-bearer-header", () => {
    const result = classify401Detailed(
      { headers: {} },
      { lookupToken: makeLookup({}), now: NOW },
    );
    assert.deepEqual(result, {
      reason: "no-bearer-header",
      hasBearer: false,
      tokenPrefix: null,
    });
  });

  it("classifies an empty Bearer value as malformed-bearer", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer " } },
      { lookupToken: makeLookup({}), now: NOW },
    );
    assert.equal(result.reason, "malformed-bearer");
    assert.equal(result.hasBearer, true);
    assert.equal(result.tokenPrefix, null);
  });

  it("classifies a token absent from the store as unknown-to-db", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer ghost1234" } },
      { lookupToken: makeLookup({}), now: NOW },
    );
    assert.equal(result.reason, "unknown-to-db");
    assert.equal(result.hasBearer, true);
    assert.equal(result.tokenPrefix, "ghost1");
  });

  it("classifies a token past its expiry as expired", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer oldtok999" } },
      {
        lookupToken: makeLookup({ oldtok999: { expiresAt: past } }),
        now: NOW,
      },
    );
    assert.equal(result.reason, "expired");
    assert.equal(result.tokenPrefix, "oldtok");
  });

  it("reports a live token as valid (caller's sanity check)", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer livetoken" } },
      {
        lookupToken: makeLookup({ livetoken: { expiresAt: future } }),
        now: NOW,
      },
    );
    assert.equal(result.reason, "valid");
    assert.equal(result.tokenPrefix, "liveto");
  });

  it("accepts ISO-8601 text timestamps (as stored by @mcpauth/auth)", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer iso00000" } },
      {
        lookupToken: makeLookup({
          iso00000: { expiresAt: "2026-04-24T11:00:00.000Z" },
        }),
        now: NOW,
      },
    );
    assert.equal(result.reason, "valid");
  });

  it("accepts epoch-seconds numeric expiries", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer numtoken" } },
      {
        lookupToken: makeLookup({
          numtoken: { expiresAt: NOW.getTime() + 60_000 },
        }),
        now: NOW,
      },
    );
    assert.equal(result.reason, "valid");
  });

  it("surfaces DB lookup failures distinctly (not as unknown-to-db)", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer boom" } },
      {
        lookupToken: () => {
          throw new Error("sqlite is on fire");
        },
        now: NOW,
      },
    );
    assert.equal(result.reason, "lookup-failed");
    assert.equal(result.tokenPrefix, "boom");
  });

  it("flags bad DB timestamps rather than treating them as valid", () => {
    const result = classify401Detailed(
      { headers: { authorization: "Bearer garbage" } },
      {
        lookupToken: makeLookup({ garbage: { expiresAt: "not-a-date" } }),
        now: NOW,
      },
    );
    assert.equal(result.reason, "bad-expiry");
  });

  it("NEVER exposes more than the first 6 chars of the token", () => {
    const secret = "s3cr3t-supersensitive-access-token-xyz";
    const result = classify401Detailed(
      { headers: { authorization: `Bearer ${secret}` } },
      { lookupToken: makeLookup({}), now: NOW },
    );
    assert.equal(result.tokenPrefix.length, 6);
    assert.ok(!result.tokenPrefix.includes("supersensitive"));
    assert.ok(!Object.values(result).some((v) => String(v).includes(secret)));
  });
});
