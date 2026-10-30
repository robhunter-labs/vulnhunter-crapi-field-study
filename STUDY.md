# Study protocol and claim boundary

## Objective

Explore whether agentic security testing can be a useful program-level force multiplier when candidate generation, evidence, human validation, and enterprise vulnerability-management intake are considered together. This single run primarily tested the first three links, not the whole enterprise workflow.

## Run shape

1. Pin VulnHunter and crAPI source revisions; use a local, intentionally vulnerable crAPI instance.
2. Qualify the target and isolate the agent’s access to approved source and local service paths.
3. Run VulnHunter Hunt once under a signed scope, bounded cost/time, and external monitor. The engine and crAPI controller in `source/` show those controls.
4. Retain generated candidate packages and machine test states without treating them as findings.
5. Reconcile the native run evidence, then prepare a separate human-review packet. A reviewer—not the agent—would have authority to accept a finding.

The study was source-led and not blind; public crAPI solution material was accessible. Fix and separate Verify were outside this run. The 46 packages split into 39 whose generated tests observed predicted behavior and 7 that remained conditional. Those are machine-test states, not distinct vulnerability counts. Human disposition remained pending; no candidate was promoted to an accepted finding. That pending status is a separate review axis, not a fourth bucket in the 46. These observations cannot support a general detection rate, false-positive rate, product ranking, or enterprise-readiness claim.

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

The public copy substitutes private absolute roots with placeholders, omits raw runtime and candidate records, and retains the original run’s code structure. The review-workbench tests are portable. The engine/controller source is for inspection and adaptation, not a reproducible one-command release. The upstream tool and target must be obtained from their own repositories and terms.
