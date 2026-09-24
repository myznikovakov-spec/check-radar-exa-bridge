"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { evaluateRobotsTxt } = require("../src/robots-policy");

test("allows when no matching robots group exists", () => {
  const r = evaluateRobotsTxt({
    robotsText: "User-agent: OtherBot\nDisallow: /private",
    targetUrl: "https://example.com/public"
  });
  assert.equal(r.allowed, true);
});

test("stops when wildcard group disallows target path", () => {
  const r = evaluateRobotsTxt({
    robotsText: "User-agent: *\nDisallow: /private",
    targetUrl: "https://example.com/private/page"
  });
  assert.equal(r.allowed, false);
  assert.equal(r.decision, "STOP_POLICY");
});

test("named CheckRadarBot group takes precedence over wildcard", () => {
  const r = evaluateRobotsTxt({
    robotsText:
      "User-agent: *\nDisallow: /\n\n" +
      "User-agent: CheckRadarBot\nAllow: /public\nDisallow: /private",
    targetUrl: "https://example.com/public/page"
  });
  assert.equal(r.allowed, true);
});

test("longest matching rule wins", () => {
  const r = evaluateRobotsTxt({
    robotsText:
      "User-agent: *\nDisallow: /catalog\nAllow: /catalog/public",
    targetUrl: "https://example.com/catalog/public/item"
  });
  assert.equal(r.allowed, true);
});

test("allow wins equal-length tie", () => {
  const r = evaluateRobotsTxt({
    robotsText:
      "User-agent: *\nDisallow: /same\nAllow: /same",
    targetUrl: "https://example.com/same"
  });
  assert.equal(r.allowed, true);
});

test("invalid target URL stops conservatively", () => {
  const r = evaluateRobotsTxt({
    robotsText: "User-agent: *\nAllow: /",
    targetUrl: "not a url"
  });
  assert.equal(r.allowed, false);
  assert.equal(r.decision, "STOP_POLICY");
});
