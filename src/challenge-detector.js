"use strict";

/**
 * Check Radar public challenge detector.
 *
 * Defensive purpose only: classify access barriers and stop safely.
 * This module never attempts to solve, bypass, evade, or replay challenges.
 */

function normalizeHeaders(headers = {}) {
  const out = {};
  if (typeof headers.forEach === "function") {
    headers.forEach((value, key) => {
      out[String(key).toLowerCase()] = String(value);
    });
    return out;
  }
  for (const [key, value] of Object.entries(headers || {})) {
    out[String(key).toLowerCase()] = Array.isArray(value)
      ? value.join(", ")
      : String(value ?? "");
  }
  return out;
}

function containsAny(text, needles) {
  return needles.find((needle) => text.includes(needle));
}

function result({
  decision,
  provider,
  category,
  confidence,
  httpStatus,
  evidence,
  manualCheckRequired,
  retryAfter = null
}) {
  return {
    decision,
    provider,
    category,
    confidence,
    http_status: Number(httpStatus || 0),
    evidence,
    manual_check_required: manualCheckRequired,
    retry_after: retryAfter,
    message_ru:
      decision === "STOP_MANUAL"
        ? "Обнаружена проверка/ограничение доступа. Автоматика остановлена; нужна ручная проверка."
        : decision === "STOP_POLICY"
          ? "Источник запрещает автоматический доступ. Автоматика остановлена."
          : decision === "BACKOFF"
            ? "Источник ограничил частоту запросов или временно недоступен. Повторные запросы приостановлены."
            : "Обычный публичный контент доступен."
  };
}

function classifyResponse(input = {}) {
  const status = Number(input.status || 0);
  const headers = normalizeHeaders(input.headers);
  const body = String(input.body || "").slice(0, 250000).toLowerCase();
  const url = String(input.url || "").toLowerCase();
  const contentType = (headers["content-type"] || "").toLowerCase();
  const retryAfter = headers["retry-after"] || null;

  if (input.robotsAllowed === false) {
    return result({
      decision: "STOP_POLICY",
      provider: "generic",
      category: "robots",
      confidence: "high",
      httpStatus: status,
      evidence: ["robots.txt disallows this target"],
      manualCheckRequired: false
    });
  }

  if (input.repeatedChallenge === true) {
    return result({
      decision: "STOP_MANUAL",
      provider: "unknown",
      category: "repeated_challenge",
      confidence: "high",
      httpStatus: status,
      evidence: ["challenge repeated for this host"],
      manualCheckRequired: true
    });
  }

  // Strong header signals first.
  if ((headers["cf-mitigated"] || "").toLowerCase() === "challenge") {
    return result({
      decision: "STOP_MANUAL",
      provider: "cloudflare",
      category: "managed_challenge",
      confidence: "high",
      httpStatus: status,
      evidence: ["cf-mitigated: challenge"],
      manualCheckRequired: true
    });
  }

  const awsAction = (headers["x-amzn-waf-action"] || "").toLowerCase();
  if (awsAction === "challenge" || awsAction === "captcha") {
    return result({
      decision: "STOP_MANUAL",
      provider: "aws_waf",
      category: awsAction === "captcha" ? "captcha" : "managed_challenge",
      confidence: "high",
      httpStatus: status,
      evidence: [`x-amzn-waf-action: ${awsAction}`],
      manualCheckRequired: true
    });
  }

  const dataDomeHeader = [
    "x-datadome",
    "x-datadomeresponse",
    "x-dd-b",
    "x-datadome-isbot"
  ].find((name) => headers[name] !== undefined);
  const cookieHeader = `${headers["set-cookie"] || ""};${headers["cookie"] || ""}`.toLowerCase();
  if (dataDomeHeader || cookieHeader.includes("datadome=")) {
    return result({
      decision: "STOP_MANUAL",
      provider: "datadome",
      category: "bot_management",
      confidence: "high",
      httpStatus: status,
      evidence: [dataDomeHeader ? `header: ${dataDomeHeader}` : "datadome cookie"],
      manualCheckRequired: true
    });
  }

  // Strong public widget/page markers.
  const strongMarkers = [
    {
      provider: "cloudflare",
      category: "captcha_or_widget",
      needles: [
        "challenges.cloudflare.com/turnstile",
        "cf-turnstile-response",
        "class=\"cf-turnstile\"",
        "class='cf-turnstile'"
      ]
    },
    {
      provider: "google_recaptcha",
      category: "captcha",
      needles: [
        "www.google.com/recaptcha/api.js",
        "g-recaptcha-response",
        "class=\"g-recaptcha\"",
        "class='g-recaptcha'",
        "grecaptcha.render"
      ]
    },
    {
      provider: "hcaptcha",
      category: "captcha",
      needles: [
        "js.hcaptcha.com/1/api.js",
        "h-captcha-response",
        "class=\"h-captcha\"",
        "class='h-captcha'",
        "hcaptcha.render"
      ]
    },
    {
      provider: "datadome",
      category: "bot_management",
      needles: ["displaydatadomecaptchapage", "datadome captcha", "datadome device check"]
    },
    {
      provider: "human_perimeterx",
      category: "bot_management",
      needles: [
        "perimeterx human challenge",
        "human human challenge",
        "px-captcha",
        "_pxappid"
      ]
    },
    {
      provider: "akamai",
      category: "bot_management",
      needles: ["akamai bot manager", "akamai challenge"]
    },
    {
      provider: "imperva",
      category: "waf_or_bot_management",
      needles: ["incapsula incident id", "req_challenged", "imperva captcha", "imperva challenge"]
    }
  ];

  for (const marker of strongMarkers) {
    const hit = containsAny(body, marker.needles);
    if (hit) {
      return result({
        decision: "STOP_MANUAL",
        provider: marker.provider,
        category: marker.category,
        confidence: "high",
        httpStatus: status,
        evidence: [`body marker: ${hit}`],
        manualCheckRequired: true
      });
    }
  }

  // Generic human-verification language.
  const genericHit = containsAny(body, [
    "verify you are human",
    "prove you are human",
    "are you a robot",
    "complete the security check",
    "browser verification",
    "checking your browser",
    "enable javascript and cookies to continue"
  ]);
  if (genericHit) {
    return result({
      decision: "STOP_MANUAL",
      provider: "generic",
      category: "human_verification",
      confidence: "medium",
      httpStatus: status,
      evidence: [`body marker: ${genericHit}`],
      manualCheckRequired: true
    });
  }

  // An unexpected HTML interstitial is suspicious when an API/non-HTML resource was expected.
  if (
    input.expectedContentType &&
    !String(input.expectedContentType).toLowerCase().includes("html") &&
    contentType.includes("text/html") &&
    [202, 401, 403, 405, 429, 503].includes(status)
  ) {
    return result({
      decision: "STOP_MANUAL",
      provider: "unknown",
      category: "unexpected_interstitial",
      confidence: "medium",
      httpStatus: status,
      evidence: [
        `expected ${input.expectedContentType}, received text/html with status ${status}`
      ],
      manualCheckRequired: true
    });
  }

  // Access controls and rate limits.
  if (status === 429) {
    return result({
      decision: "BACKOFF",
      provider: "generic",
      category: "rate_limit",
      confidence: "high",
      httpStatus: status,
      evidence: [retryAfter ? `Retry-After: ${retryAfter}` : "HTTP 429"],
      manualCheckRequired: false,
      retryAfter
    });
  }

  if (status === 503) {
    return result({
      decision: "BACKOFF",
      provider: "generic",
      category: "temporary_unavailable",
      confidence: "medium",
      httpStatus: status,
      evidence: ["HTTP 503"],
      manualCheckRequired: false,
      retryAfter
    });
  }

  if (status === 401 || status === 403) {
    // Cloudflare PAT subrequest 401 can be expected during a challenge flow.
    if (
      status === 401 &&
      url.includes("/cdn-cgi/challenge-platform/") &&
      url.includes("/pat/")
    ) {
      return result({
        decision: "ALLOW",
        provider: "cloudflare",
        category: "challenge_support_subrequest",
        confidence: "medium",
        httpStatus: status,
        evidence: ["expected Cloudflare PAT support subrequest"],
        manualCheckRequired: false
      });
    }

    return result({
      decision: "STOP_MANUAL",
      provider: "generic",
      category: status === 401 ? "authentication_required" : "access_denied",
      confidence: "medium",
      httpStatus: status,
      evidence: [`HTTP ${status}`],
      manualCheckRequired: true
    });
  }

  const wallHit = containsAny(body, [
    "login required",
    "sign in to continue",
    "log in to continue",
    "subscribe to continue",
    "subscription required",
    "paywall"
  ]);
  if (wallHit) {
    return result({
      decision: "STOP_MANUAL",
      provider: "generic",
      category: "access_restriction",
      confidence: "medium",
      httpStatus: status,
      evidence: [`body marker: ${wallHit}`],
      manualCheckRequired: true
    });
  }

  return result({
    decision: "ALLOW",
    provider: "unknown",
    category: "ordinary_content",
    confidence: "medium",
    httpStatus: status,
    evidence: [],
    manualCheckRequired: false
  });
}

module.exports = { classifyResponse, normalizeHeaders };
