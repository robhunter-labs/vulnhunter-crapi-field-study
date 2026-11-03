# Capital One’s VulnHunter on OWASP crAPI — an independent field study

What does an agentic security tool actually give a penetration-testing program after it has generated candidates—and what still has to happen before an enterprise can use them? This repository accompanies [the field study on Rob Hunter Works](https://robhunterworks.com/writing/vulnhunter-crapi/). It is independent work, not a Capital One or OWASP project, endorsement, or benchmark.

The subject was [Capital One’s VulnHunter](https://github.com/capitalone/vulnhunter), pinned at [`4042d34609ff85e0029dd55743b9c3f677cc984a`](https://github.com/capitalone/vulnhunter/commit/4042d34609ff85e0029dd55743b9c3f677cc984a), run against [OWASP crAPI](https://github.com/OWASP/crAPI) v1.1.6, pinned at [`700f03d12a392d9e408260b4beae72ed02a4a1a4`](https://github.com/OWASP/crAPI/commit/700f03d12a392d9e408260b4beae72ed02a4a1a4), in a local live instance. Capital One released an unusually substantial tool and workflow to the community. This study examines its Hunt path and the experiment system built around it; it does not repackage VulnHunter or crAPI source.

**Status: Observed.** One controlled run, recorded here. More studies are indexed in [ai-security-field-lab](https://github.com/robhunter-labs/ai-security-field-lab).

## Start here

**Try it in 5 minutes (no target, no API key):** the [synthetic first-use exercise](source/review-workbench/FIRST_USE.md) builds one sample review packet and shows the decision a human still has to make. Python 3.9+, standard library only.

The controlled, source-led run retained **46 candidate packages**. Generated tests observed the predicted behavior for **39** packages; **7** remained conditional. **Human review was not completed, so none of the candidates was promoted to an accepted finding.** The 39 tests are not 39 distinct vulnerabilities, and the pending review cannot be read as 46 rejected findings or a false-positive rate. The run was not blind; public crAPI solution material remained available. VulnHunter Fix and separate Verify were not run.

The diagrams show the operating model: [master map](diagrams/00_master_map.svg), [harness architecture](diagrams/05_harness_architecture.svg), [evidence lineage](diagrams/10_evidence_lineage.svg), and [authority boundary](diagrams/11_trust_authority.svg). Read [STUDY.md](STUDY.md) for the protocol, export-to-enterprise gap, and limits.

## Actual experiment source

This is the historical source of the experiment controls, not a toy reimplementation:

The agent runtime was Claude Code. The engine requested the `opus` alias and refused completion unless the root model resolved to `claude-opus-5`; subagents were allowed `claude-opus-4-8` or `claude-sonnet-5` (see `source/engine/full_vulnhunt_a4.py`).

| Component | What it did |
|---|---|
| [`source/engine/`](source/engine/) | Pinned source/tool preparation, signed scope, budget/identity controls, isolated agent run, raw capture, progress monitoring, and validation. The engine originated in an earlier Juice Shop run and was adapted for crAPI. |
| [`source/controller/`](source/controller/) | crAPI target adapter, local runtime boundary, scope contract, prompt, and post-run revalidation. |
| [`source/qualification/`](source/qualification/) | Local crAPI runtime qualification, including controlled account setup and cross-principal test behavior. |
| [`source/review-workbench/`](source/review-workbench/) | Candidate packet preparation, evidence-binding checks, explicit human dispositions, and portable provider-free tests. |

The study code is **not a turn-key scanner or a portable crAPI harness**. It is the source of one controlled run. Local filesystem roots were replaced with conspicuous `/path/to/...` placeholders before publication, but study-specific schema names, fixed run IDs, and local temporary-path conventions remain in the code. These are historical labels, not a general configuration interface. In particular, the crAPI controller imports an engine and qualifier through a placeholder study root; the qualifier expects Compose overrides, an image lock, source-admission controls, and other inputs that are not distributed here. The controller/qualifier cannot be run end-to-end from a fresh clone. The same holds for `source/controller/tests/`, which records the historical controller checks but needs the private study root to import. Do not replace those placeholders and run against a real target without authorization, source and dependency review, containment, exact pins, and a new scope.

The original private runtime logs, credentials/tokens generated in the lab, signed scope, raw model transcripts, and complete candidate corpus are intentionally not in this repository. Their omission prevents a byte-for-byte re-run of the historical experiment. No live secret or personal home-directory path is intended to be published; generated local receipts can still contain a caller's absolute input paths and must be reviewed before sharing.

The review-workbench and qualification tests run with Python 3.9 or newer, standard library only:

```sh
cd source/review-workbench && python3 test_review_workbench.py     # or: python3 -m unittest discover
cd ../qualification && python3 test_private_answer_key.py
```

These commands run provider-free fixtures; they do not validate a new VulnHunter run. For a safe, runnable introduction to the review packet and its human-decision boundary, follow [the synthetic first-use exercise](source/review-workbench/FIRST_USE.md).

### Limits of the review tooling

- `prepare_review.py` needs a completed results directory, a matching native validation record, and a raw event log. Its direct-PASS path refuses missing or mismatched path/digest bindings, synthetic or defect-bearing records, and result changes observed while building the packet. These checks bind evidence but do **not** authenticate who produced the validation record; `DIRECT_NATIVE_PASS` is not independent proof against a malicious producer.
- The qualifier creates the hidden key exclusively in owner-private directories, and the model settings deny both `/private/tmp` and `/tmp` spellings. Those settings have not been tested inside the actual provider sandbox. The model and controller share an OS account, so local file mode alone is not a confidentiality boundary.
- In the public copy, the egress-denial probe host was replaced with a reserved example domain. Do not use this historical fixed-path evaluator for real credentials or on a shared host.

## What the reader can take away

The source shows the difference between the **tool** (VulnHunter), the **experiment harness** (the external controller and bounded runtime), and the **human review workbench**. The generated packages carried useful technical evidence, but the enterprise intake record still needed a named reviewer, business impact, CVSS assessment, asset owner, ticket routing, remediation decision, and retest plan. More candidate throughput is valuable only when those next stages can absorb it.

This study is one independent learning event, not the first round of a scheduled head-to-head comparison, and it makes no ranking claim.

Copyright © 2026 Rob Hunter. Original study code, documentation, and diagrams here are released under the MIT license in `LICENSE`. VulnHunter and crAPI remain their owners’ projects under their own terms. The synthetic crAPI test-account pattern in the qualification source is not an actual credential.

Found a gap in the controls or a better way to make a review packet useful? Open an issue.
