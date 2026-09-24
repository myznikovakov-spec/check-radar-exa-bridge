"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyResponse } = require("../src/challenge-detector");

test("detects DataDome captcha page marker", () => {
  const r = classifyResponse({
    status: 403,
    headers: { "content-type": "text/html" },
    body: "<html><script>displayDataDomeCaptchaPage()</script></html>"
  });

  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "datadome");
  assert.equal(r.manual_check_required, true);
});

test("detects HUMAN / PerimeterX challenge", () => {
  const r = classifyResponse({
    status: 403,
    headers: { "content-type": "text/html" },
    body: "<div>PerimeterX Human Challenge</div><div id=\"px-captcha\"></div>"
  });

  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "human_perimeterx");
  assert.equal(r.manual_check_required, true);
});

test("detects Akamai Bot Manager challenge marker", () => {
  const r = classifyResponse({
    status: 403,
    headers: { "content-type": "text/html" },
    body: "<html><title>Akamai Bot Manager</title><p>Akamai challenge</p></html>"
  });

  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "akamai");
  assert.equal(r.manual_check_required, true);
});

test("detects Imperva / Incapsula challenge marker", () => {
  const r = classifyResponse({
    status: 403,
    headers: { "content-type": "text/html" },
    body: "<html><p>Incapsula incident ID</p><p>REQ_CHALLENGED</p></html>"
  });

  assert.equal(r.decision, "STOP_MANUAL");
  assert.equal(r.provider, "imperva");
  assert.equal(r.manual_check_required, true);
});
