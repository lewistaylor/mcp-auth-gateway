import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  JSONRPC_SESSION_TERMINATED,
  JSONRPC_INTERNAL_ERROR,
  RECOVERABLE_UPSTREAM_ERRORS,
  shouldSynthesizeSessionTerminated,
  buildSessionTerminatedBody,
  buildUpstreamErrorBody,
} from "../lib/jsonrpc.mjs";

/**
 * Unit tests for the JSON-RPC helpers in lib/jsonrpc.mjs.
 *
 * The contract these tests guard is the gateway's promise to MCP
 * clients: a stale or temporarily-unreachable upstream session is
 * always surfaced as `404 + JSON-RPC -32002 "Session terminated"` so
 * Claude / Cursor reinitialize automatically. Anything else — including
 * an "innocent" 502 during a Railway redeploy — strands the client.
 */

describe("error code constants", () => {
  it("exports the wire values used by upstream MCP backends", () => {
    // These two numbers are the entire wire contract with the MCP
    // client. Any change here is a breaking API change, so a test
    // that pins the constants is worth its weight.
    assert.equal(JSONRPC_SESSION_TERMINATED, -32002);
    assert.equal(JSONRPC_INTERNAL_ERROR, -32000);
  });
});

describe("RECOVERABLE_UPSTREAM_ERRORS", () => {
  it("covers exactly the failure modes seen during a Railway redeploy", () => {
    // The deploy lifecycle on Railway produces, in rough order:
    //   1. ECONNREFUSED — old container is gone, new container hasn't
    //      yet bound the port.
    //   2. ECONNRESET — old container's existing connections are torn
    //      down mid-flight.
    //   3. EHOSTUNREACH — networking layer transiently routes nowhere
    //      (rare, but observed on the 24 April 2026 incident).
    //   4. ENOTFOUND / EAI_AGAIN — internal DNS update lag during the
    //      service rename window.
    //   5. ETIMEDOUT / UPSTREAM_TIMEOUT — old container accepts the
    //      TCP handshake but never sends a response.
    //
    // If we add an upstream failure category to observability.mjs and
    // forget to update this set, the redeploy-recovery path silently
    // regresses, so this test is intentionally exhaustive.
    assert.deepEqual(
      [...RECOVERABLE_UPSTREAM_ERRORS].sort(),
      [
        "connection-refused",
        "connection-reset",
        "dns-failure",
        "host-unreachable",
        "socket-timeout",
        "upstream-timeout",
      ],
    );
  });
});

describe("shouldSynthesizeSessionTerminated", () => {
  it("returns false when no Mcp-Session-Id was carried", () => {
    // Without a session id the request is almost certainly an
    // `initialize` attempt. Synthesizing -32002 there would lie ("you
    // had no session to terminate") AND would not actually help the
    // client recover — it has nothing to retry.
    for (const kind of RECOVERABLE_UPSTREAM_ERRORS) {
      assert.equal(
        shouldSynthesizeSessionTerminated(kind, null),
        false,
        `kind=${kind} sid=null`,
      );
      assert.equal(
        shouldSynthesizeSessionTerminated(kind, ""),
        false,
        `kind=${kind} sid=""`,
      );
      assert.equal(
        shouldSynthesizeSessionTerminated(kind, undefined),
        false,
        `kind=${kind} sid=undefined`,
      );
    }
  });

  it("returns true for every recoverable kind when a session id is present", () => {
    for (const kind of RECOVERABLE_UPSTREAM_ERRORS) {
      assert.equal(
        shouldSynthesizeSessionTerminated(kind, "abc-123"),
        true,
        `kind=${kind}`,
      );
    }
  });

  it("returns false for non-recoverable kinds", () => {
    // These don't correlate with "the upstream redeployed and forgot
    // your session", so synthesizing -32002 would mislead the client
    // into a reinit loop.
    const nonRecoverable = [
      "unknown",
      "EPIPE",
      "EACCES",
      "TLS-handshake-failed",
    ];
    for (const kind of nonRecoverable) {
      assert.equal(
        shouldSynthesizeSessionTerminated(kind, "abc-123"),
        false,
        `kind=${kind}`,
      );
    }
  });

  it("rejects non-string error kinds defensively", () => {
    // classifyUpstreamError() is supposed to always return a string,
    // but if a refactor ever lets through null / undefined we don't
    // want to start synthesizing -32002 for arbitrary errors.
    assert.equal(
      shouldSynthesizeSessionTerminated(null, "sid"),
      false,
    );
    assert.equal(
      shouldSynthesizeSessionTerminated(undefined, "sid"),
      false,
    );
    assert.equal(shouldSynthesizeSessionTerminated(42, "sid"), false);
    assert.equal(shouldSynthesizeSessionTerminated({}, "sid"), false);
  });
});

describe("buildSessionTerminatedBody", () => {
  it("matches the shape the upstream MCP backends emit", () => {
    // The gateway's synthesized body has to be byte-for-byte
    // indistinguishable from what e.g. notion-mcp / gmail-mcp send,
    // because the MCP client cannot tell us which one it just got and
    // both have to drive the same reinit path.
    const body = JSON.parse(buildSessionTerminatedBody(null));
    assert.deepEqual(body, {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32002, message: "Session terminated" },
    });
  });

  it("echoes a numeric request id when one is supplied", () => {
    const body = JSON.parse(buildSessionTerminatedBody(7));
    assert.equal(body.id, 7);
    assert.equal(body.error.code, -32002);
  });

  it("echoes a string request id when one is supplied", () => {
    const body = JSON.parse(buildSessionTerminatedBody("req-xyz"));
    assert.equal(body.id, "req-xyz");
  });

  it("defaults the id to null when called with no args", () => {
    const body = JSON.parse(buildSessionTerminatedBody());
    assert.equal(body.id, null);
  });
});

describe("buildUpstreamErrorBody", () => {
  it("produces a -32000 envelope with the supplied message", () => {
    const body = JSON.parse(buildUpstreamErrorBody("Upstream timeout"));
    assert.deepEqual(body, {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32000, message: "Upstream timeout" },
    });
  });

  it("echoes a request id when supplied", () => {
    const body = JSON.parse(
      buildUpstreamErrorBody("Service unavailable", "abc"),
    );
    assert.equal(body.id, "abc");
  });
});
