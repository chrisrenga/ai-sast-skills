# AI SAST skills

A proposed Scottish Government version of AI-assisted static application security testing
(SAST): four agent skills that take a department from "which repositories?" to owner-ready
reports. Every finding is proven by a local test or clearly marked as unproven, and every
sentence stays within what the evidence supports.

> **Status: proposal for discussion.** This is not an official Scottish Government product,
> and it is not endorsed by GC3 or Cloudflare. It builds on public work by both; see
> [docs/design.md](docs/design.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## The skills

| Skill | Use it to |
|---|---|
| [`sast-triage`](skills/sast-triage/SKILL.md) | Decide which repositories in an estate deserve a full assessment, in what order, and who owns each. |
| [`sast-assess`](skills/sast-assess/SKILL.md) | Assess one repository: reconnaissance, coverage-led hunting and independent validation on Cloudflare's security-audit method, under departmental run control. Also answers "is this reported vulnerability real?" |
| [`sast-report`](skills/sast-report/SKILL.md) | Turn a finished run into finding reports, validation requests, an executive summary, SARIF, Jira and ServiceNow import files, and one pack per owning team. |
| [`sast-qa`](skills/sast-qa/SKILL.md) | Check the whole set before anything is shared: wording, counts, secrets, checksums and rules of engagement. |

## How it works

```text
approved scope ─▶ sast-triage ─▶ review queue
                                   │ per repository
                                   ▼
        prepare-scan-copy ─▶ sast-assess ─▶ findings.json + register.json + run-record.json
                                   │            (three validators must pass)
                                   ▼
                              sast-report ─▶ reports, SARIF, tickets, owner packs
                                   │
                                   ▼
                               sast-qa ─▶ QA.md: safe to share / human review / withheld
```

The rules that matter most:

- **Evidence bar.** `confirmed` needs an observed result from a sandboxed local check,
  ideally a regression test that fails on the untouched source, reproduced by a fresh agent.
  A model's reading of source is not enough. Everything else is `needs_validation`, with no
  severity and an exact check for the owner, or `rejected`.
- **Run control.** The department approves the scope, attacker classes, thresholds and
  execution policy. The agent works on a sanitised scan copy, treats everything in the
  repository as data rather than instructions, touches no live system, and redacts secrets.
- **Claims control.** Each record carries what is safe to say, what is not, and what becomes
  safe if validated. Reports and tickets are built from those statements.
- **Checked by code.** Zero-dependency scripts validate the records and the report pack.
  The register validator computes whether the same model found and verified a finding, so
  that cannot be misreported.

## Install

All four skills are meant to be installed together: `sast-report` and `sast-qa` use files in
`sast-assess`.

**Claude Code** (as a plugin):

```text
/plugin marketplace add chrisrenga/ai-sast-skills
/plugin install ai-sast-skills@ai-sast-skills
```

**Other agents** that support the Agent Skills format, using the
[Skills CLI](https://skills.sh):

```sh
npx skills add https://github.com/chrisrenga/ai-sast-skills
```

Or copy the four folders under `skills/` into your agent's skills directory, side by side.

## Requirements

- An agent client with tool use and sub-agents, using a model route the department has
  approved.
- Node.js 20 or later for the scripts.
- An isolated environment to run the agent in, and a sandbox for target code if execution
  is approved. [skills/sast-assess/references/sandbox.md](skills/sast-assess/references/sandbox.md)
  describes both.
- [gitleaks](https://github.com/gitleaks/gitleaks), recommended for the scan-copy secret scan.

## Quick start

```sh
# 1. Make a sanitised scan copy at one commit
node skills/sast-assess/scripts/prepare-scan-copy.mjs --repo ~/src/example-service --ref main --out /assessments/A1/scan-copy
```

Then, from an assessment workspace outside the scan copy, ask the agent:

```text
Run a standard sast-assess of /assessments/A1/scan-copy. The approved scope is in
/assessments/A1/scope.md. Write outputs to /assessments/A1/run-1.
```

Follow with "Produce the sast-report pack for /assessments/A1/run-1" and then "Run sast-qa
on /assessments/A1/run-1".

[skills/sast-assess/examples/sample-run/](skills/sast-assess/examples/sample-run/) shows
what a finished run's records look like, with one confirmed, one needs-validation and one
rejected record.

## Repository layout

```text
skills/
  sast-triage/       SKILL.md
  sast-assess/       SKILL.md, references/, templates/, scripts/, examples/,
                     cloudflare/ (vendored method, MIT)
  sast-report/       SKILL.md, templates/, scripts/
  sast-qa/           SKILL.md, scripts/
docs/
  design.md          what this keeps from GC3 and Cloudflare, and what it changes
  adoption.md        decisions a department needs to make, and a suggested pilot
```

## Tests

```sh
npm test
```

This runs the tests for this pack's scripts and for Cloudflare's validators.

## Never commit findings here

Scan copies, run outputs, findings and reports describe unfixed weaknesses in someone's
systems. They belong in the department's approved output location, never in this
repository or any other. `.gitignore` excludes the usual output folders as a backstop, not
as a control.

## Licence

MIT, see [LICENSE](LICENSE). `skills/sast-assess/cloudflare/` is MIT, copyright
Cloudflare, Inc. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
