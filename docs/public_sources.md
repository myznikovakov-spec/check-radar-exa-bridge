# Public sources for challenge detection rules

This file records public vendor documentation used to build defensive challenge detection. The bridge only detects and stops; it does not implement bypass techniques.

## CAPTCHA and challenge systems

- Google reCAPTCHA v2: https://developers.google.com/recaptcha/docs/display
  - Public markers include `g-recaptcha`, `g-recaptcha-response`, and the Google reCAPTCHA API script.
- hCaptcha configuration: https://docs.hcaptcha.com/configuration
  - Public markers include the hCaptcha API script, widget container, response field, challenge/error states, and rate-limited state.
- Cloudflare Turnstile client rendering: https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/
  - Public markers include `cf-turnstile`, `cf-turnstile-response`, and `challenges.cloudflare.com/turnstile`.
- Cloudflare Challenge Page response detection: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  - Cloudflare documents `cf-mitigated: challenge` as the reliable response marker.
- Cloudflare challenge concepts: https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/
  - Covers Challenge Pages, Turnstile, JavaScript Detections, and managed challenge behavior.

## WAF / bot-management systems

- AWS WAF CAPTCHA and Challenge action behavior: https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html
  - AWS documents `x-amzn-waf-action: challenge` with HTTP 202 and `x-amzn-waf-action: captcha` with HTTP 405.
- DataDome response pages: https://docs.datadome.co/docs/response-pages
  - Publicly documents Device Check, CAPTCHA, and hard-block response page types.
- DataDome Protection API: https://docs.datadome.co/reference/validate-request
  - Documents DataDome response headers and challenge decisions.
- HUMAN Challenge: https://docs.humansecurity.com/applications/human-challenge
- HUMAN Challenge customization: https://docs.humansecurity.com/applications/customize-challenge-page
  - Public documentation includes Human Challenge/PerimeterX terminology and block-page integration.
- Akamai Bot Manager detection methods: https://techdocs.akamai.com/cloud-security/docs/detection-methods
- Akamai challenge action: https://techdocs.akamai.com/terraform/docs/bmgr-ds-challenge-action
- Imperva / Thales Cloud WAF error pages and codes: https://docs.imperva.com/bundle/cloud-application-security/page/error-codes.htm

## Crawl and rate-limit behavior

- Robots Exclusion Protocol (RFC 9309): https://www.rfc-editor.org/rfc/rfc9309
- HTTP 429 Too Many Requests (RFC 6585): https://www.rfc-editor.org/rfc/rfc6585
- HTTP semantics / Retry-After: https://www.rfc-editor.org/rfc/rfc9110

## Maintenance rule

Provider behavior changes. When a vendor publishes a new reliable signal, add it only if it is useful for **detection/stop/manual escalation**. Do not add evasion, fingerprint spoofing, CAPTCHA-solving, proxy rotation, or other bypass logic.
