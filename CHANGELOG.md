# Changelog

## 0.1.0 (6 November 2026)

First proposal.

- Four skills: `sast-triage`, `sast-assess`, `sast-report`, `sast-qa`.
- Cloudflare's security-audit skill vendored at `c1c8a8c` as the assessment method.
- Run control, evidence register, run record and claims control, following the practices of
  the GC3 AI SAST Toolkit in new text.
- Scripts: `prepare-scan-copy.mjs`, `validate-register.mjs`, `to-sarif.mjs`,
  `to-tickets.mjs` and `check-pack.mjs`, with tests and a worked sample run.
