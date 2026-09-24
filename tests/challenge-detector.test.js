"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyResponse } = require("../src/challenge-detector");

test("detects Cloudflare managed challenge header", () => {
  const r = classifyResponse({
    status: 403,
    headers: { "cf-mitigated": "challenge", "content-type": "text/html" }
  });
  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "cloudflare");
});

test("detects AWS WAF challenge", () => {
  const r = classifyResponse({
    status: 202,
    headers: { "x-amzn-waf-action": "challenge" }
  });
  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "aws_waf");
});

test("detects reCAPTCHA markup", () => {
  const r = classifyResponse({
    status: 200,
    body: '<div class="g-recaptcha" data-sitekey="x"></div>'
  });
  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "google_recaptcha");
});

test("detects hCaptcha markup", () => {
  const r = classifyResponse({
    status: 200,
    body: '<script src="https://js.hcaptcha.com/1/api.js"></script>'
  });
  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "hcaptcha");
});

test("detects Turnstile markup", () => {
  const r = classifyResponse({
    status: 200,
    body: '<div class="cf-turnstile"></div>'
  });
  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "cloudflare");
});

test("detects DataDome response header", () => {
  const r = classifyResponse({
    status: 403,
    headers: { "X-DataDome": "protected" }
  });
  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "datadome");
});

test("429 backs off and honors Retry-After", () => {
  const r = classifyResponse({
    status: 429,
    headers: { "Retry-After": "120" }
  });
  assert.equal(r.decision, "BACKOFF");
  assert.equal(r.retry_after, "120");
});

test("robots disallow stops by policy", () => {
  const r = classifyResponse({ status: 200, robotsAllowed: false });
  assert.equal(r.decision, "STOP_POLICY");
});

test("ordinary page is allowed", () => {
  const r = classifyResponse({
    status: 200,
    headers: { "content-type": "text/html" },
    body: "<html><title>Public page</title><p>Hello</p></html>"
  });
  assert.equal(r.decision, "ALLOW");
});
