# Adopting the pack: a suggested pilot

This is a proposal. Nothing here assumes how a department's security function is organised;
each step names the decision it needs.

## Decisions before a first run

| Decision | Why it matters |
|---|---|
| **Model route and data terms.** Which agreement and endpoint the agent uses, whether prompts and outputs are kept by the provider, and where they are processed. | Source code leaves the department's boundary for the model. This is the main data-protection question. |
| **Where runs happen.** An isolated assessment environment that meets layer 1 of `sandbox.md`. | Keeps the target's code and the agent away from personal credentials and other systems. |
| **Execution policy.** Whether target code may run in a sandbox (`sandboxed-local`) or not at all (`none`). | Without execution nothing reaches `confirmed`; the output is still useful, but every item needs owner validation. |
| **Retention.** How long scan copies, run outputs and reports are kept, where, and who deletes them. | Run outputs describe unfixed weaknesses. |
| **Thresholds and attacker classes.** The department's own scale and the attackers it cares about. | The pack never chooses these. |
| **Reporting route.** Where owner packs go, and who signs off a report as safe to share. | `sast-qa` marks artefacts consistent with the evidence, but a person approves release. |
| **Licensing of GC3-derived material.** GC3 has no licence file. This pack re-expresses its ideas in new text and copies none of it, but if the department wants to build on GC3 directly, it would be worth asking its authors to publish a licence, for example the Open Government Licence. | Clean reuse. |

## Pilot

1. **Choose one repository** whose weaknesses are already known from a recent penetration test
   or code review, so the results can be compared against something.
2. **Prepare a scan copy** with `prepare-scan-copy.mjs`, and clear the secret scan.
3. **Run `sast-assess` with the `quick` profile** and an agent-invocation budget. Record the
   cost, the time, and the agents used.
4. **Compare**: which known issues were found, which were missed, what new candidates appeared,
   and how many `needs_validation` items owners could settle quickly.
5. **Run `sast-report` and `sast-qa`**, and send one owner pack through the real reporting route.
6. **Review**: was the evidence bar right, were the claims usable, did anything in run control
   get in the way? Adjust the pack and record the change in its changelog.
7. **Repeat with `standard`** on a second repository before considering a wider rollout, then
   use `sast-triage` to plan across an estate.

## What to measure

- Known issues found, against the reference review.
- Confirmed findings later accepted by owners, against those disputed.
- `needs_validation` items settled by owners, and how long that took.
- Agent invocations and model cost per run.
- Anything that reached an artefact which `sast-qa` should have stopped.

Cloudflare reports that a single run found roughly half of what repeated runs found
together. Plan for more than one run per important repository, using the ledger so each run
targets the gaps left by the last.
