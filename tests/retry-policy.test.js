"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  MAX_RETRIES,
  parseRetryAfter,
  getRetryPlan
} = require("../src/retry-policy");

test("Retry-After seconds are honored", () => {
  assert.equal(parseRetryAfter("120", 0), 120000);
});

test("429 without Retry-After waits 15 minutes", () => {
  const r = getRetryPlan({ status: 429, attempt: 0, nowMs: 0 });
  assert.equal(r.retry, true);
  assert.equal(r.delay_ms, 15 * 60 * 1000);
});

test("503 without Retry-After waits 5 minutes", () => {
  const r = getRetryPlan({ status: 503, attempt: 0, nowMs: 0 });
  assert.equal(r.retry, true);
  assert.equal(r.delay_ms, 5 * 60 * 1000);
});

test("Retry-After overrides fallback delay", () => {
  const r = getRetryPlan({
    status: 429,
    retryAfter: "600",
    attempt: 0,
    nowMs: 0
  });
  assert.equal(r.delay_ms, 600000);
});

test("retry limit stops the host", () => {
  const r = getRetryPlan({
    status: 429,
    attempt: MAX_RETRIES,
    nowMs: 0
  });
  assert.equal(r.retry, false);
  assert.equal(r.action, "STOP_HOST");
});

test("ordinary statuses are not retried by this policy", () => {
  const r = getRetryPlan({ status: 200, attempt: 0 });
  assert.equal(r.retry, false);
  assert.equal(r.action, "NO_RETRY_POLICY");
});
