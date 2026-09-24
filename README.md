# Check Radar — Exa Bridge

Public bridge for safe source checking with Exa.

## Purpose

This repository contains only public-safe detection rules and handling policy for website access barriers such as CAPTCHA, managed challenges, rate limits, WAF blocks, robots restrictions, login walls, and browser verification pages.

It must not contain private Check Radar data, API keys, tokens, credentials, internal databases, or sensitive business logic.

## Canonical rules

For runtime decisions, use only these canonical files:

- `config/challenge-signatures.json`
- `prompts/exa_challenge_policy.md`
- `src/challenge-detector.js`

Other policy/signature files that may appear in the repository are informational or legacy unless explicitly promoted here. This prevents duplicate or older rules from overriding the canonical detector.

## Core safety behavior

When a source returns a CAPTCHA, anti-bot challenge, managed challenge, repeated access denial, or another uncertain verification barrier:

1. Stop automated retries for that host.
2. Return an explicit alert with the URL, detected provider/category, evidence, HTTP status, and timestamp.
3. Mark the source as `manual_check_required`.
4. Do not attempt to bypass CAPTCHA, fingerprinting, access controls, authentication, or site restrictions.
5. After a human manually passes the check, automation may resume only while ordinary access remains available.
6. A practical manual-session refresh target is at most about once per 24 hours when that is sufficient, but any new challenge immediately stops automation again.
7. If challenges become frequent, keep the host in manual mode to reduce ban risk.
8. Respect robots.txt, rate limits, Retry-After, and publisher access rules.

## Files

- `config/challenge-signatures.json` — machine-readable challenge/anti-bot signatures.
- `prompts/exa_challenge_policy.md` — Exa-facing handling instructions.
- `docs/public_sources.md` — public documentation used to build the signatures.
- `src/challenge-detector.js` — dependency-free response classifier.
- `tests/challenge-detector.test.js` — regression tests.

This bridge is designed to detect and stop on access controls, not to defeat them.
