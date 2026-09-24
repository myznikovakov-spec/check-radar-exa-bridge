"use strict";

/**
 * Conservative retry policy for Check Radar.
 *
 * No aggressive retries:
 * - only HTTP 429 / 503 are retryable here;
 * - Retry-After always wins when valid;
 * - at most 2 retry attempts per request;
 * - after that, stop the host and require later/manual review.
 */

const MAX_RETRIES = 2;
const DEFAULT_429_DELAY_MS = 15 * 60 * 1000;
const DEFAULT_503_DELAY_MS = 5 * 60 * 1000;

function parseRetryAfter(value, nowMs = Date.now()) {
  if (value === null || value === undefined || value === "") return null;

  const raw = String(value).trim();

  if (/^\d+$/.test(raw)) {
    return Math.max(0, Number(raw) * 1000);
  }

  const dateMs = Date.parse(raw);
  if (Number.isNaN(dateMs)) return null;

  return Math.max(0, dateMs - nowMs);
}

function getRetryPlan({
  status,
  retryAfter = null,
  attempt = 0,
  nowMs = Date.now()
} = {}) {
  const code = Number(status || 0);

  if (code !== 429 && code !== 503) {
    return {
      retry: false,
      action: "NO_RETRY_POLICY",
      reason: "status_not_retryable"
    };
  }

  if (attempt >= MAX_RETRIES) {
    return {
      retry: false,
      action: "STOP_HOST",
      reason: "retry_limit_reached",
      max_retries: MAX_RETRIES
    };
  }

  const headerDelay = parseRetryAfter(retryAfter, nowMs);
  const fallbackDelay =
    code === 429 ? DEFAULT_429_DELAY_MS : DEFAULT_503_DELAY_MS;

  return {
    retry: true,
    action: "BACKOFF",
    reason: retryAfter ? "retry_after_or_safe_fallback" : "safe_fallback",
    delay_ms: headerDelay ?? fallbackDelay,
    retry_at_ms: nowMs + (headerDelay ?? fallbackDelay),
    next_attempt: attempt + 1,
    max_retries: MAX_RETRIES
  };
}

module.exports = {
  MAX_RETRIES,
  parseRetryAfter,
  getRetryPlan
};
