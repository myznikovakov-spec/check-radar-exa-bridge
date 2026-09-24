"use strict";

/**
 * Minimal conservative robots.txt evaluator for Check Radar.
 *
 * Scope of this patch:
 * - parse User-agent / Allow / Disallow;
 * - prefer the named CheckRadarBot group, otherwise use "*";
 * - longest matching path wins; Allow wins equal-length ties;
 * - if robots.txt explicitly disallows the target, return STOP_POLICY.
 *
 * This module does not fetch robots.txt itself and does not bypass rules.
 */

const DEFAULT_USER_AGENT = "CheckRadarBot";

function stripComment(line) {
  const i = line.indexOf("#");
  return (i >= 0 ? line.slice(0, i) : line).trim();
}

function parseRobotsTxt(text = "") {
  const groups = [];
  let current = null;

  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = stripComment(rawLine);
    if (!line) continue;

    const i = line.indexOf(":");
    if (i < 0) continue;

    const key = line.slice(0, i).trim().toLowerCase();
    const value = line.slice(i + 1).trim();

    if (key === "user-agent") {
      if (!current || current.hasRules) {
        current = { agents: [], rules: [], hasRules: false };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      continue;
    }

    if ((key === "allow" || key === "disallow") && current) {
      current.hasRules = true;
      current.rules.push({
        type: key,
        path: value
      });
    }
  }

  return groups;
}

function chooseGroups(groups, userAgent = DEFAULT_USER_AGENT) {
  const ua = String(userAgent).toLowerCase();

  const named = groups.filter((g) =>
    g.agents.some((a) => a !== "*" && ua.includes(a))
  );
  if (named.length) return named;

  return groups.filter((g) => g.agents.includes("*"));
}

function pathMatches(pathname, rulePath) {
  if (rulePath === "") return false;
  return pathname.startsWith(rulePath);
}

function evaluateRobotsTxt({
  robotsText = "",
  targetUrl,
  userAgent = DEFAULT_USER_AGENT
} = {}) {
  let pathname = "/";
  try {
    pathname = new URL(String(targetUrl)).pathname || "/";
  } catch {
    return {
      allowed: false,
      decision: "STOP_POLICY",
      reason: "invalid_target_url"
    };
  }

  const groups = parseRobotsTxt(robotsText);
  const selected = chooseGroups(groups, userAgent);

  if (!selected.length) {
    return {
      allowed: true,
      decision: "ALLOW",
      reason: "no_matching_robots_group"
    };
  }

  const matches = selected
    .flatMap((g) => g.rules)
    .filter((r) => pathMatches(pathname, r.path))
    .sort((a, b) => {
      const byLength = b.path.length - a.path.length;
      if (byLength !== 0) return byLength;
      if (a.type === b.type) return 0;
      return a.type === "allow" ? -1 : 1;
    });

  if (!matches.length) {
    return {
      allowed: true,
      decision: "ALLOW",
      reason: "no_matching_rule"
    };
  }

  const winningRule = matches[0];
  const allowed = winningRule.type === "allow";

  return {
    allowed,
    decision: allowed ? "ALLOW" : "STOP_POLICY",
    reason: allowed ? "robots_allow" : "robots_disallow",
    matched_rule: winningRule
  };
}

module.exports = {
  DEFAULT_USER_AGENT,
  parseRobotsTxt,
  evaluateRobotsTxt
};
