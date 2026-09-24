# Exa challenge / anti-bot policy

Apply this policy to every fetched source before treating the response as usable content.

## Goal

Detect access barriers early, stop safely, and ask for a human pass when needed. Do not bypass or evade website protections.

## Required decision

Return one of:

- `ALLOW` — ordinary public content is accessible.
- `STOP_MANUAL` — CAPTCHA, human verification, WAF/bot challenge, login wall, ambiguous access denial, or repeated challenge. Stop automated requests to the host and notify the user.
- `STOP_POLICY` — robots.txt or another explicit publisher rule disallows access.
- `BACKOFF` — temporary rate limit or overload. Honor `Retry-After` when present; never hammer the host.

## Detection order

1. Check explicit response headers:
   - Cloudflare: `cf-mitigated: challenge`.
   - AWS WAF: `x-amzn-waf-action: challenge|captcha`.
   - DataDome indicators such as `X-DataDome*`, `X-DD-B`, or a `datadome` session cookie when exposed.
2. Check known public widget/page markers:
   - Google reCAPTCHA.
   - hCaptcha.
   - Cloudflare Turnstile.
   - DataDome challenge/block/device-check pages.
   - HUMAN / PerimeterX Human Challenge.
   - Akamai Bot Manager challenge pages when identifiable.
   - Imperva / Incapsula challenge or block pages.
3. Check generic human-verification text and unexpected HTML where a non-HTML resource was expected.
4. Check HTTP access/rate signals:
   - `429`: BACKOFF.
   - `401` or `403`: STOP_MANUAL unless clearly explained by a harmless expected subrequest.
   - `503`: if challenge markers exist => STOP_MANUAL; otherwise treat as transient service failure and back off.
5. Check robots.txt / publisher restrictions before crawling deeper.

## Mandatory behavior on challenge

- Immediately stop automatic retries for that host.
- Notify the user in Russian with:
  - affected URL/host;
  - detected provider or `unknown`;
  - category;
  - HTTP status;
  - strongest evidence;
  - action required: manual passage.
- Mark the host/source as `manual_check_required`.
- Preserve logs/evidence.
- Do not rotate identities, spoof fingerprints, solve CAPTCHA automatically, use CAPTCHA-solving services, or otherwise evade controls.
- After the user manually passes the check, resume only while normal access remains available.
- Treat roughly one manual pass per 24 hours as a practical target only when that is enough for the session. If a new challenge appears sooner, stop again.
- If challenges recur frequently, keep the host in manual mode to reduce ban risk.

## Output schema

```json
{
  "decision": "ALLOW | STOP_MANUAL | STOP_POLICY | BACKOFF",
  "provider": "cloudflare | google_recaptcha | hcaptcha | aws_waf | datadome | human_perimeterx | akamai | imperva | generic | unknown",
  "category": "captcha | managed_challenge | bot_management | access_denied | authentication_required | rate_limit | robots | ordinary_content",
  "confidence": "high | medium | low",
  "http_status": 200,
  "evidence": ["short evidence only"],
  "manual_check_required": false,
  "message_ru": "Короткое понятное уведомление пользователю"
}
```

When uncertain whether a page is genuine content or a verification barrier, prefer `STOP_MANUAL`.
