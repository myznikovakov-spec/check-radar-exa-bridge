"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  safeUrl,
  buildAccessEvent,
  toJsonLine
} = require("../src/access-event-log");

test("safeUrl removes query strings and fragments", () => {
  const url = safeUrl("https://example.com/path?q=secret#token");
  assert.equal(url, "https://example.com/path");
});

test("buildAccessEvent records only safe access metadata", () => {
  const event = buildAccessEvent({
    input: {
      url: "https://example.com/private/page?api_key=secret#frag",
      status: 403,
      headers: { cookie: "secret=1" },
      body: "sensitive response body"
    },
    handling: {
      action: "STOP",
      stop: true,
      notify: true,
      detection: {
        provider: "cloudflare",
        category: "managed_challenge",
        confidence: "high",
        http_status: 403,
        manual_check_required: true,
        retry_after: null
      }
    },
    timestamp: "2026-09-25T00:00:00.000Z"
  });

  assert.deepEqual(event, {
    event: "access_check",
    timestamp: "2026-09-25T00:00:00.000Z",
    host: "example.com",
    url: "https://example.com/private/page",
    action: "STOP",
    stop: true,
    notify: true,
    provider: "cloudflare",
    category: "managed_challenge",
    confidence: "high",
    http_status: 403,
    manual_check_required: true,
    retry_after: null
  });

  const serialized = toJsonLine(event);
  assert.equal(serialized.includes("api_key"), false);
  assert.equal(serialized.includes("secret"), false);
  assert.equal(serialized.includes("cookie"), false);
  assert.equal(serialized.includes("sensitive response body"), false);
});

test("invalid URL is logged conservatively", () => {
  const event = buildAccessEvent({
    input: { url: "not a url", status: 0 },
    handling: { action: "STOP", stop: true, notify: true },
    timestamp: "2026-09-25T00:00:00.000Z"
  });

  assert.equal(event.host, "unknown");
  assert.equal(event.url, "");
});
