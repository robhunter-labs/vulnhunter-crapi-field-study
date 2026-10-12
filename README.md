# Capital One’s VulnHunter × OWASP crAPI — independent field study

What does an agentic security tool actually give a penetration-testing program after it has generated candidates—and what still has to happen before an enterprise can use them? This repository accompanies [the field study on Rob Hunter Works](https://robhunterworks.com/writing/vulnhunter-crapi/). It is independent work, not a Capital One or OWASP project, endorsement, or benchmark.

The subject was [Capital One’s VulnHunter](https://github.com/capitalone/vulnhunter), pinned at `4042d34609ff85e0029dd55743b9c3f677cc984a`, run against [OWASP crAPI](https://github.com/OWASP/crAPI), pinned at [`700f03d12a392d9e408260b4beae72ed02a4a1a4`](https://github.com/OWASP/crAPI/commit/700f03d12a392d9e408260b4beae72ed02a4a1a4), in a local live instance. Capital One released an unusually substantial tool and workflow to the community. This study examines its Hunt path and the experiment system built around it; it does not repackage VulnHunter or crAPI source.

## Start here

The controlled, source-led run produced **46 candidate packages**: **39 machine-reproduced behaviors**, **7 conditional**, and **zero human-accepted findings** at the review boundary. These are states in one workflow, not a false-positive rate or tool-accuracy score. The run was not blind; public crAPI solution material remained available. VulnHunter Fix and separate Verify were not run.

The diagrams show the operating model: [master map](diagrams/00_master_map.svg), [harness architecture](diagrams/05_harness_architecture.svg), [evidence lineage](diagrams/10_evidence_lineage.svg), and [authority boundary](diagrams/11_trust_authority.svg). Read [STUDY.md](STUDY.md) for the protocol, export-to-enterprise gap, and limits.

## Actual experiment source

This is the historical source of the experiment controls, not a toy reimplementation:

| Component | What it did |
|---|---|
| [`source/engine/`](source/engine/) | Pinned source/tool preparation, signed scope, budget/identity controls, isolated agent run, raw capture, progress monitoring, and validation. The engine originated in an earlier Juice Shop run and was adapted for crAPI. |
| [`source/controller/`](source/controller/) | crAPI target adapter, local runtime boundary, scope contract, prompt, and post-run revalidation. |
| [`source/qualification/`](source/qualification/) | Local crAPI runtime qualification, including controlled account setup and cross-principal test behavior. |
| [`source/review-workbench/`](source/review-workbench/) | Candidate packet preparation, immutable binding checks, explicit human dispositions, and 12 portable provider-free tests. |

The study code is **not a turn-key scanner**. Its frozen run IDs, digests, paths, model assumptions, container images, signed scope, and source-custody dependencies describe the original controlled run. Machine-local roots have been replaced with obvious `/path/to/...` placeholders, and private control-plane names and paths have been generalized in this public copy. Those substitutions make the source inspectable, not directly executable against the original environment. Do not execute the engine/controller against a real target without your own authorization, dependency review, exact source pins, isolation, and a new scope. The original private runtime logs, credentials/tokens generated in the lab, signed scope, raw model transcripts, and complete candidate corpus are intentionally not in this repository. That omission prevents a byte-for-byte re-run of the original experiment; it does not alter the reported outcome.

The review-workbench code is independently testable with Python’s standard library:

```sh
cd source/review-workbench
python3 test_review_workbench.py
```

## What the reader can take away

The source shows the difference between the **tool** (VulnHunter), the **experiment harness** (our external controller and bounded runtime), and the **human review workbench**. The generated packages carried useful technical evidence, but the enterprise intake record still needed a named reviewer, business impact, CVSS assessment, asset owner, ticket routing, remediation decision, and retest plan. More candidate throughput is valuable only when those next stages can absorb it.

The next proof of concept should compare several tool starting points—including VulnHunter, Strix, and Pentagi—against the same program-level intake, reviewer-effort, integration, repeatability, and total-cost questions. This repository makes no ranking claim.

Copyright © 2026 Rob Hunter. Original study code, documentation, and diagrams here are released under the MIT license in `LICENSE`. VulnHunter and crAPI remain their owners’ projects under their own terms. The synthetic crAPI test-account pattern in the qualification source is not an actual credential.
