# Public sources for challenge detection rules

This file records public vendor documentation used to build defensive challenge detection. The bridge only detects and stops; it does not implement bypass techniques.

## CAPTCHA and challenge systems

- Google reCAPTCHA v2: https://developers.google.com/recaptcha/docs/display
  - Public markers include `g-recaptcha`, `g-recaptcha-response`, and the Google reCAPTCHA API script.
- hCaptcha configuration: https://docs.hcaptcha.com/configuration
  - Public markers include the hCaptcha API script, widget container, response field, challenge/error states, and rate-limited state.
- Cloudflare Turnstile: https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/
  - Public markers include `cf-turnstile`, `cf-turnstile-response`, and `challenges.cloudflare.com/turnstile`.
- Cloudflare Challenge Page response detection: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  - Cloudflare documents `cf-mitigated: challenge` as the reliable response marker.
- Cloudflare challenge concepts: https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/
- Arkose Labs client-side instructions: https://developer.arkoselabs.com/docs/standard-setup
  - Public client API URLs and Enforcement Challenge integration are documented.
- Arkose Labs iframe setup: https://developer.arkoselabs.com/docs/iframe-setup-guide
  - Publicly documents `iframe.arkoselabs.com` and challenge event names.
- Friendly Captcha v2 install: https://developer.friendlycaptcha.com/docs/v2/getting-started/install
  - Public marker: `frc-captcha` and Friendly Captcha SDK scripts.
- GeeTest CAPTCHA v4 web integration: https://docs.geetest.com/BehaviorVerification/deploy/client/web
  - Public marker: `static.geetest.com/v4/gt4.js`.
- GeeTest CAPTCHA v3 web integration: https://docs.geetest.com/captcha/deploy/client/web
  - Public markers include `initGeetest` and GeeTest static JS resources.

## WAF / bot-management systems

- AWS WAF CAPTCHA and Challenge behavior: https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html
  - AWS documents `x-amzn-waf-action: challenge` with HTTP 202 and `x-amzn-waf-action: captcha` with HTTP 405.
- DataDome response pages: https://docs.datadome.co/docs/response-pages
- DataDome Protection API: https://docs.datadome.co/reference/validate-request
- HUMAN Challenge: https://docs.humansecurity.com/applications/human-challenge
- HUMAN Challenge customization: https://docs.humansecurity.com/applications/customize-challenge-page
- Akamai Bot Manager detection methods: https://techdocs.akamai.com/cloud-security/docs/detection-methods
- Akamai challenge action: https://techdocs.akamai.com/terraform/docs/bmgr-ds-challenge-action
- Imperva / Thales Cloud WAF error pages: https://docs.imperva.com/bundle/cloud-application-security/page/error-codes.htm
- F5 Bot Defense action reference: https://clouddocs.f5.com/api/irules/BOTDEFENSE__action.html
  - Publicly documents browser challenge, CAPTCHA challenge, redirect challenge, block, and internal response actions.
- Radware Bot Manager release/support documentation: https://support.radware.com/
  - Public pages describe CAPTCHA redirection and crypto challenge mitigation.
- Kasada Bot Defense: https://www.kasada.io/bot-defense
  - Publicly describes invisible client-side challenges. No stable public response marker is relied on by this detector.

## Crawl and rate-limit behavior

- Robots Exclusion Protocol (RFC 9309): https://www.rfc-editor.org/rfc/rfc9309
- HTTP 429 Too Many Requests (RFC 6585): https://www.rfc-editor.org/rfc/rfc6585
- HTTP semantics / Retry-After (RFC 9110): https://www.rfc-editor.org/rfc/rfc9110

## Maintenance rule

Provider behavior changes. Add a signature only when public documentation gives a reliable signal useful for detection/stop/manual escalation. Do not add evasion, fingerprint spoofing, CAPTCHA-solving, proxy rotation, or other bypass logic.
