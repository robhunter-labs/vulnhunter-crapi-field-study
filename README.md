# Capital One’s VulnHunter on OWASP crAPI: an independent field study

What does an agentic security tool actually give a penetration-testing program after it has generated candidates, and what still has to happen before an enterprise can use them? I set up Capital One’s VulnHunter against a target I controlled and watched where the work went. This repository holds the working side of that field study, [*Capital One’s VulnHunter: From Source Code to Live Testing*](https://robhunterworks.com/writing/vulnhunter-crapi/). It is independent work, not a Capital One or OWASP project, endorsement, or benchmark.

## What the run showed

**Status: Observed in one controlled run.** The run retained **46 candidate packages**. Generated tests observed the predicted behavior for **39**; **7** remained conditional. **Human review was not completed in this run, so no candidate was promoted to an accepted finding.** A reviewer, not the agent, holds that authority.

The generated packages carried useful technical evidence. An enterprise intake record would still need a named reviewer, business impact, Common Vulnerability Scoring System (CVSS) assessment, asset owner, ticket routing, remediation decision, and retest plan. More candidate throughput is valuable only when those next stages can absorb it.

That is why the source keeps apart three layers that are easy to collapse: the **tool** (VulnHunter), the **experiment harness** (the external controller and bounded runtime), and the **human review workbench**. The [authority boundary diagram](diagrams/11_trust_authority.svg) shows which role held which power.

## What it does not show

The 39 tests are not 39 distinct vulnerabilities, and the unfinished review cannot be read as 46 rejected findings or a false-positive rate. The run was not blind; public crAPI solution material remained available. VulnHunter Fix and separate Verify were not run. The study makes no ranking claim.

The subject was [Capital One’s VulnHunter](https://github.com/capitalone/vulnhunter) against [OWASP crAPI](https://github.com/OWASP/crAPI) v1.1.6 in a local live instance. Capital One released an unusually substantial tool and workflow to the community; this study examines its Hunt path and repackages neither project’s source. Pins, the agent runtime and tooling limits are in [STUDY.md](STUDY.md#source-runtime-and-review-tooling-limits).

## Start here

| Route | Open | What you get |
|---|---|---|
| **Try the synthetic review exercise** (5 minutes, no target, no API key) | [FIRST_USE.md](source/review-workbench/FIRST_USE.md) | One sample review packet and the decision a human still has to make. |
| **Inspect the historical run** | [STUDY.md](STUDY.md), then [Actual experiment source](#actual-experiment-source) | Protocol, export-to-enterprise gap and limits. A record to read, not a rerun. |

Cite the [v1.0.0 release](https://github.com/robhunter-labs/vulnhunter-crapi-field-study/releases/tag/v1.0.0); send corrections and questions to [the study discussion](https://github.com/robhunter-labs/vulnhunter-crapi-field-study/discussions/4). More studies: [ai-security-field-lab](https://github.com/robhunter-labs/ai-security-field-lab).

## Actual experiment source

The historical source of the experiment controls. It is **not a turn-key scanner** and can’t run end-to-end from a fresh clone; do not run it against a real target without authorization and a new scope.

| Component | What it did |
|---|---|
| [`source/engine/`](source/engine/) | Pinned source/tool preparation, signed scope, budget/identity controls, isolated agent run, raw capture, progress monitoring, and validation. |
| [`source/controller/`](source/controller/) | crAPI target adapter, local runtime boundary, scope contract, prompt, and post-run revalidation. |
| [`source/qualification/`](source/qualification/) | Local crAPI runtime qualification, including controlled account setup and cross-principal test behavior. |
| [`source/review-workbench/`](source/review-workbench/) | Candidate packet preparation, evidence-binding checks, explicit human dispositions, and portable provider-free tests. |

Copyright © 2026 Rob Hunter. Original study code, documentation, and diagrams here are released under the MIT license in `LICENSE`. VulnHunter and crAPI remain their owners’ projects under their own terms.

Found a gap in the controls or a better way to make a review packet useful? Open an issue.
