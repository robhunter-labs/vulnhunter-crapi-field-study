# Study protocol and claim boundary

## Objective

This study explored whether agentic security testing can be a useful force multiplier for a penetration-testing program when candidate generation, evidence, human validation, and enterprise vulnerability-management intake are considered together. This single run reached candidate generation and evidence; human validation was prepared but not completed, and enterprise intake was not tested.

## Run shape

1. Pin VulnHunter and crAPI source revisions; use a local, intentionally vulnerable crAPI instance.
2. Qualify the target and isolate the agent’s access to approved source and local service paths.
3. Run VulnHunter Hunt once under a signed scope, bounded cost/time, and external monitor. The engine and crAPI controller in `source/` show those controls.
4. Retain generated candidate packages and machine test states without treating them as findings.
5. Reconcile the native run evidence, then prepare a separate human-review packet. A reviewer, not the agent, would have authority to accept a finding.

The study was source-led and not blind; public crAPI solution material was accessible. Fix and separate Verify were outside this run. The 46 packages split into 39 whose generated tests observed predicted behavior and 7 that remained conditional. Those are machine-test states, not distinct vulnerability counts. Human disposition remained pending; no candidate was promoted to an accepted finding. That pending status is a separate review axis, not another bucket in the 46. These observations cannot support a general detection rate, false-positive rate, product ranking, or enterprise-readiness claim.

## From export to enterprise record

The selected packages supplied endpoint/request shape, source location, classification, proof material, and executable test material. The curated record did **not** yet supply a complete enterprise intake object:

| Available in selected candidate material | Still needed before organizational intake |
|---|---|
| Technical hypothesis and source path | Named human reviewer and disposition |
| Request and endpoint shape | Affected asset and service owner |
| Proof document and generated test | Reproduction steps consolidated for a separate tester; screenshots where useful |
| Machine test state | Business impact, realistic preconditions, and severity/CVSS assessment |
| Candidate identifier | Ticket ownership, remediation decision, retest criteria, and closure authority |

This is an observation about this run’s curated export, not a claim that VulnHunter as a product cannot provide these fields in other workflows or versions.

## Why the source is here

The experiment harness was external to VulnHunter. It controlled source pins, run scope, budget, target setup, identity and containment, evidence capture, and handoff. The agent executed the tool’s Hunt workflow; the external controller did not become a second pentester or secretly grade findings. The review workbench held the human authority boundary after the run. This distinction matters when an organization evaluates whether to integrate a tool into its existing penetration-testing and vulnerability-management program.

The public copy replaces private absolute roots with placeholders, omits raw runtime and candidate records, and retains the original run’s code structure. The review-workbench and qualification tests are portable; the controller tests need the private study root to import. The engine/controller source is for inspection and adaptation, not a reproducible one-command release. The upstream tool and target must be obtained from their own repositories and terms.

For the wider operating model, see the [master map](diagrams/00_master_map.svg), [harness architecture](diagrams/05_harness_architecture.svg) and [evidence lineage](diagrams/10_evidence_lineage.svg).

## Source, runtime and review-tooling limits

The subject was [Capital One’s VulnHunter](https://github.com/capitalone/vulnhunter), pinned at [`4042d34609ff85e0029dd55743b9c3f677cc984a`](https://github.com/capitalone/vulnhunter/commit/4042d34609ff85e0029dd55743b9c3f677cc984a), run against [OWASP crAPI](https://github.com/OWASP/crAPI) v1.1.6, pinned at [`700f03d12a392d9e408260b4beae72ed02a4a1a4`](https://github.com/OWASP/crAPI/commit/700f03d12a392d9e408260b4beae72ed02a4a1a4), in a local live instance. Capital One released an unusually substantial tool and workflow to the community. This study examines its Hunt path and the experiment system built around it; it does not repackage VulnHunter or crAPI source.

This study is one independent learning event, not the first round of a scheduled head-to-head comparison, and it makes no ranking claim.

The engine originated in an earlier run against OWASP Juice Shop and was adapted for crAPI.

The agent runtime was Claude Code. The engine requested the `opus` alias and refused completion unless the root model resolved to `claude-opus-5`; subagents were allowed `claude-opus-4-8` or `claude-sonnet-5` (see `source/engine/full_vulnhunt_a4.py`).

The study code is **not a turn-key scanner or a portable crAPI harness**; it is the source of one controlled run. Local filesystem roots became conspicuous `/path/to/...` placeholders, while study-specific schema names, fixed run IDs and temporary-path conventions remain as historical labels, not a configuration interface. The crAPI controller imports the engine and qualifier through a placeholder study root, and the qualifier expects Compose overrides, an image lock, source-admission controls and other inputs not distributed here, so neither they nor `source/controller/tests/` can run end-to-end from a fresh clone. Do not replace those placeholders and run against a real target without authorization, source and dependency review, containment, exact pins, and a new scope.

The private runtime logs, lab-generated credentials/tokens, signed scope, raw model transcripts and complete candidate corpus are intentionally omitted, which prevents a byte-for-byte re-run. No live secret or personal home-directory path is intended to be published; generated local receipts can still contain a caller's absolute input paths and must be reviewed before sharing.

The synthetic crAPI test-account pattern in the qualification source is not an actual credential.

The review-workbench and qualification tests run provider-free fixtures with Python 3.9 or newer, standard library only. They do not validate a new VulnHunter run. The synthetic review exercise in [FIRST_USE.md](source/review-workbench/FIRST_USE.md) was checked on the included synthetic fixtures.

```sh
cd source/review-workbench && python3 test_review_workbench.py     # or: python3 -m unittest discover
cd ../qualification && python3 test_private_answer_key.py
```

### Limits of the review tooling

- `prepare_review.py` needs a completed results directory, a matching native validation record and a raw event log. Its direct-PASS path refuses missing or mismatched path/digest bindings, synthetic or defect-bearing records, and results that change while the packet is built. These checks bind evidence but do **not** authenticate who produced the validation record; `DIRECT_NATIVE_PASS` is not independent proof against a malicious producer.
- The qualifier creates the hidden key only in owner-private directories, and the model settings deny both `/private/tmp` and `/tmp` spellings; those settings were not tested inside the actual provider sandbox. The model and controller share an OS account, so local file mode alone is not a confidentiality boundary.
- In the public copy, the egress-denial probe host was replaced with a reserved example domain. Do not use this historical fixed-path evaluator for real credentials or on a shared host.
