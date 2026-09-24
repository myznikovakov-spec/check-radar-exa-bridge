"use strict";

/**
 * Safe structured event log for access checks.
 *
 * Important:
 * - never stores response bodies;
 * - never stores request/response headers;
 * - never stores cookies, credentials, query strings, fragments, or tokens;
 * - intended for JSONL or another append-only event sink chosen by the caller.
 */

function safeUrl(rawUrl = "") {
  try {
    const u = new URL(String(rawUrl));
    return `${u.protocol}//${u.host}${u.pathname || "/"}`;
  } catch {
    return "";
  }
}

function hostFromUrl(rawUrl = "") {
  try {
    return new URL(String(rawUrl)).host;
  } catch {
    return "unknown";
  }
}

function buildAccessEvent({
  input = {},
  handling = {},
  timestamp = new Date().toISOString()
} = {}) {
  const detection = handling.detection || {};

  return {
    event: "access_check",
    timestamp,
    host: hostFromUrl(input.url),
    url: safeUrl(input.url),
    action: handling.action || detection.decision || "UNKNOWN",
    stop: Boolean(handling.stop),
    notify: Boolean(handling.notify),
    provider: detection.provider || "unknown",
    category: detection.category || "unknown",
    confidence: detection.confidence || "unknown",
    http_status: Number(detection.http_status || input.status || 0),
    manual_check_required: Boolean(detection.manual_check_required),
    retry_after: detection.retry_after || null
  };
}

function toJsonLine(event) {
  return JSON.stringify(event);
}

module.exports = {
  safeUrl,
  buildAccessEvent,
  toJsonLine
};
