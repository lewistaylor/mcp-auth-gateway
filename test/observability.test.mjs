import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  logJson,
  classifyUpstreamError,
  classify401,
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

describe("classify401", () => {
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
