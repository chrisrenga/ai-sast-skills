---
name: sast-triage
description: Triage many approved repositories before AI-assisted SAST, for public-sector security teams. Use to decide which repositories in an estate or portfolio deserve a full sast-assess run, in what order and at what depth, with the evidence for each choice and who owns each one. Produces a prioritised review queue, attribution and routing, exclusions with reasons, and an endpoint authorisation inventory. Finds no vulnerabilities itself.
---

# SAST triage

Decide where a full assessment is worth spending, and hand `sast-assess` enough to start
each run without repeating discovery. Triage makes no vulnerability claims.

Run control from `sast-assess` applies in full: read
`../sast-assess/references/run-control.md` first. Triage needs an approved scope that lists
the repositories, and reads only their scan copies or an approved metadata inventory.

## Steps

1. **Enumerate** the approved repositories. Give each a stable id (`R001`, `R002`, ...) and
   record name, URL, default branch and the commit read. If the commit is unknown, say so.
   Never invent one.
2. **Exclude** with a reason: archived and not deployed, forks or mirrors where upstream is
   authoritative, empty, documentation only, static content with no server-side logic,
   templates and prototypes with no deployment, or third-party code the department does not
   control. An excluded repository that still looks risky or possibly deployed goes on the
   watchlist with the evidence that would bring it back.
3. **Read just enough** of each remaining repository to justify a decision: README,
   `CODEOWNERS`, service catalogue files, manifests and lockfiles, route and controller files,
   authentication and session code, Dockerfiles, CI workflows and infrastructure as code.
   Record every file read. Run cheap deterministic searches before model reading.
4. **Prove reachability** for every repository you select. Name the attacker class (from the
   scope), the entry point, how attacker input gets there, the sensitive effect worth
   reviewing, and the evidence. Mark the proof `source-visible`, `deployment-inferred` or
   `config-dependent`. Do not select a repository because it is generally important.
5. **Map endpoints** for web, API and admin services: route groups, handlers, methods,
   authentication, endpoint authorisation, object or tenant scope, CSRF or session controls,
   feature flags, privileged backend clients, and gaps. Global middleware, CSRF tokens and
   feature flags are not endpoint authorisation.
6. **Attribute and route.** For each selected repository, record who owns it and how you
   know:

   | Source | Confidence |
   |---|---|
   | Department attribution registry or repository custom properties | high |
   | Literal tags in active infrastructure as code or deployment files | medium |
   | Tags resolved from variables, with the environment named | medium |
   | Unresolved expressions or commented-out tags | low |
   | Topics, README, `CODEOWNERS`, catalogue files | routing signal only |

   Keep conflicting evidence. Where no owner is confirmed, give a routing confirmation id
   (`RC001`) and an owner-confirmation task. Never use "UNKNOWN" as an owner.
7. **Prioritise** on two separate scales:

   | Priority | Typical repository |
   |---|---|
   | P1 | Shared security library, identity service, token or policy component, or internet-facing service with sensitive data and wide reach |
   | P2 | Internet-facing service with sensitive workflows, personal data, admin functions or identity integration |
   | P3 | Probably internet-facing, moderate data sensitivity, unclear exposure |
   | P4 | Internal tooling, deployment or infrastructure code with indirect reach |
   | P5 | Narrow, little attack surface seen |

   Confidence is `high` (routes, auth code or deployment files read), `medium` (some source,
   partly inferred) or `low` (mostly metadata). Break ties by shared security components
   first, then explicit over inferred exposure, wider reach, more sensitive data, and less
   attacker effort.
8. **Queue** the selected repositories. Shared libraries go before the services that use
   them. Give each a suggested `sast-assess` profile (`quick`, `standard`, `deep`) and scope
   (whole repository or named paths), and its first-look files.
9. **Recommend what next**: continue triage, proceed to assessments, narrow to a pattern
   hunt across repositories, or pause for owner validation. Say what evidence would change
   the recommendation.

## Outputs

Write to the scope's output location, under `triage/`:

- `repositories.json`: one object per repository with `repository_id`, name, URL, branch,
  commit, `decision` (`assess`, `sample`, `defer`, `duplicate-pattern`, `excluded`),
  priority, confidence, exposure, `reachability_proof`, attribution, `routing_id`,
  `files_read`, `first_look`, suggested profile, queue position and reason.
- `endpoint-authorisation.json`: the endpoint map from step 5.
- `TRIAGE.md`: summary counts (enumerated, excluded, selected, attribution coverage), the
  ranked table, exclusions grouped by reason, the watchlist, the queue with reasons, and the
  recommendation.

Triage records are routing and priority signals only. Nothing in them is a finding.
