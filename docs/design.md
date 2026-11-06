# Design notes

This pack started from two public sources:

- the [GC3 AI SAST Toolkit](https://github.com/uk-gov-cyber/GC3-AI-SAST-Toolkit), a staged
  prompt pack with reporting templates, written for UK government departments;
- [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), the
  skill behind Cloudflare's write-up
  [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness).

GC3 got a great deal right for a public-sector setting: the department sets thresholds and
attacker classes; evidence is labelled on separate axes; severity is kept apart from
confidence; and every record carries a negative control. It also has careful
claims wording for anything that leaves the team, a coverage record for what was reviewed
but not promoted, a reachability proof and endpoint authorisation map, a rule that a chain
is no stronger than its weakest link, honest recording of which model did what, and
reporting built for routing work to many owners.

Cloudflare's skill covers much of the same ground with a stricter evidence bar and with
code that checks its own outputs.

This pack keeps GC3's departmental layer and runs it on Cloudflare's method.

## What changed, and why

### 1. Skills instead of a prompt pack loaded from the toolkit root

GC3 is run by starting a coding agent in the toolkit directory, so that `CLAUDE.md` and
`AGENTS.md` load, then working through five prompts in order. Its two instruction files are
kept identical by hand.

Here the same workflow is four skills in the open Agent Skills format. Any agent client
that supports it loads them, and a skill's description triggers it when the request fits.
Each loads its detail only when needed. Nothing has to be kept in lockstep. Teams can install
`sast-triage` and `sast-report` without running assessments themselves.

### 2. A higher bar for "confirmed"

In GC3, a source-to-sink trace that a model has read can be `SAST-confirmed`, and the
confirmation prompts may be answered by the same model that found the issue. GC3 is open
about this: it asks reports to say so. But a careful reading by a model is still a reading.

Here, `confirmed` needs an observed result from a bounded local check in a sandbox,
reproduced by a fresh agent that did not find the issue: Cloudflare's rule. Preferably the
check is a regression test that fails on the untouched source; the same test then shows the
fix works. Anything short of that is `needs_validation`, which has no severity and must name
the exact fact that would settle it. A department that does not approve execution still gets
useful output, but nothing in it is `confirmed`.

GC3's labels are kept in `register.json` so existing departmental processes can still read
them. The validator enforces how they follow from the verdict, so a `needs_validation` record
cannot be described as `locally-validated`.

### 3. The sandbox is specified, not assumed

GC3's guidance assumes a hardened sandbox and a sanitised copy of the repository, but the
repository does not define either. Here:

- `prepare-scan-copy.mjs` makes the copy. It exports one commit with no `.git/`, removes
  likely credential files, replaces symbolic links, renames agent instruction files, runs a
  secret scan, and writes a manifest of what it did.
- Run control says where the agent runs: no personal credentials, and network egress only
  to the approved model route.
- `references/sandbox.md` gives a concrete container recipe for running target code, meeting
  each of Cloudflare's controls: no network, empty environment, read-only source, scratch-only
  writes and resource limits.

### 4. Outputs that are checked by code, not only by a prompt

GC3's QA stage is a prompt asking a model to check consistency. Here, four zero-dependency
scripts do the mechanical part:

- Cloudflare's two validators, for findings and coverage;
- `validate-register.mjs`, for the departmental layer (labels follow verdicts, claims are
  present and not overstated, chains respect the weakest link, routing and actions are
  complete, and the run record's same-model flag is computed, not declared);
- `check-pack.mjs`, for the reports (secrets, unfilled templates, checksums, and counts
  reconciled against the register).

The QA skill then reads only where the scripts cannot judge.

### 5. Four additions to Cloudflare's method

Cloudflare's skill does not, at the vendored commit:

- tell agents to treat the repository's own text as untrusted. Run control adds a verbatim
  block to every agent prompt, and the scan-copy script stops agent clients loading the
  target's instruction files;
- record which model and version ran each stage. The run record does, and it shows whether
  verification was independent;
- carry claims wording. The register does, and every report and ticket is built from it;
- run scanners. An optional pre-pass feeds leads to reconnaissance. Every lead ends with a
  disposition, and none is ever a finding.

### 6. Reporting kept, formats trimmed

GC3's routing model is kept: attribution with sources and confidence, routing confirmation
ids, owner packs, ticket import files and report-back templates. Its OPTRS and VXDF outputs
are left out to keep the pack small. SARIF and the ticket files are generated by scripts
from the records, so they cannot disagree with them. A department that relies on OPTRS or
VXDF can add a converter alongside `to-sarif.mjs`.

## What stays the same

The department owns the scope, thresholds and attacker classes. No live systems are
touched. Secrets are redacted. Missing facts are written as missing. Reviewed but not
promoted work is recorded. A named human accepts every finding.
