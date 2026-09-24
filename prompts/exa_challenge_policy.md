# Exa challenge / anti-bot policy

Apply this policy to every fetched source before treating the response as usable content.

## Goal

Detect access barriers early, stop safely, and ask for a human pass when needed. Do not bypass or evade website protections.

## Required decision

Return one of:

- `ALLOW` — ordinary public content is accessible.
- `STOP_MANUAL` — CAPTCHA, human verification, WAF/bot challenge, login wall, ambiguous access denial, or repeated challenge.
- `STOP_POLICY` — robots.txt or another explicit publisher rule disallows access.
- `BACKOFF` — temporary rate limit or overload. Honor `Retry-After`; never hammer the host.

## Detection order

1. Check explicit response headers:
   - Cloudflare: `cf-mitigated: challenge`.
   - AWS WAF: `x-amzn-waf-action: challenge|captcha`.
   - DataDome: documented DataDome response headers/session markers when exposed.
2. Check page-wide challenge/block indicators:
   - DataDome, HUMAN/PerimeterX, Akamai, Imperva, F5 Bot Defense, Radware, Kasada, or generic human-verification text.
3. Treat embedded widget families as contextual, not automatic blockers:
   - Google reCAPTCHA
   - hCaptcha
   - Cloudflare Turnstile
   - Arkose Labs / FunCaptcha / Enforcement Challenge
   - Friendly Captcha
   - GeeTest
   An embedded widget on an ordinary HTTP 200 article/contact page is not by itself a reason to stop. Stop when the widget gates the requested content, accompanies denial/challenge status, replaces expected content, or appears with human-verification language.
4. Check HTTP access/rate signals:
   - `429`: BACKOFF.
   - `401` or `403`: STOP_MANUAL unless clearly explained by a harmless expected subrequest.
   - `503`: challenge markers => STOP_MANUAL; otherwise BACKOFF.
5. Check robots.txt / publisher restrictions before crawling deeper.

## Mandatory behavior on challenge

- Immediately stop automatic retries for that host.
- Notify the user in Russian with URL/host, provider/category, HTTP status, strongest evidence, and action required.
- Mark the host/source as `manual_check_required`.
- Preserve logs/evidence.
- Do not rotate identities, spoof fingerprints, solve CAPTCHA automatically, use CAPTCHA-solving services, or otherwise evade controls.
- After the user manually passes the check, resume only while normal access remains available.
- Treat roughly one manual pass per 24 hours as a practical target only when that is enough for the session. Any new challenge stops automation again.
- If challenges recur frequently, keep the host in manual mode to reduce ban risk.

## Output schema

```json
{
  "decision": "ALLOW | STOP_MANUAL | STOP_POLICY | BACKOFF",
  "provider": "cloudflare | google_recaptcha | hcaptcha | arkose | friendly_captcha | geetest | aws_waf | datadome | human_perimeterx | akamai | imperva | f5_bot_defense | radware | kasada | generic | unknown",
  "category": "captcha | enforcement_challenge | managed_challenge | bot_management | access_denied | authentication_required | rate_limit | robots | ordinary_content",
  "confidence": "high | medium | low",
  "http_status": 200,
  "evidence": ["short evidence only"],
  "manual_check_required": false,
  "message_ru": "Короткое понятное уведомление пользователю"
}
```

When uncertain whether a page is genuine content or a verification barrier, prefer `STOP_MANUAL`.
