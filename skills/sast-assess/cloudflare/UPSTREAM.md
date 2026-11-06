# Vendored copy of Cloudflare's security-audit skill

These files are a copy of `skills/security-audit/` from
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill),
used under the MIT licence in [LICENSE](LICENSE).

| | |
|---|---|
| Upstream commit | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (14 September 2026, "Clarify guidance and full audit modes") |
| Copied on | 6 November 2026 |
| Changes | One: upstream `SKILL.md` is renamed `METHOD.md` so that skill loaders do not register it as a second, separate skill. No file content is changed. |

Where these files say `SKILL.md`, read `METHOD.md`.

`sast-assess` runs this method under its own run control, evidence register and claims
control. Where `../references/run-control.md` and these files differ, run control wins.

## Refreshing

Upstream is still changing. To take a newer version, copy the upstream
`skills/security-audit/` directory over this one, rename `SKILL.md` to `METHOD.md`, update
the commit above, and record the new commit in each run's `run-record.json`
(`tools.cloudflare_method_commit`). Read the upstream diff first: a change to
`report-schema.json` or to a verdict rule can affect `register.json` and the scripts in
`sast-report`.
