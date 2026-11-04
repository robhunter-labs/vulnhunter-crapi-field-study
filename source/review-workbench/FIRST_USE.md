# First use: read a candidate without promoting it

The workbench turns a completed, validated experiment run into a packet for human review. The historical results and raw log are private, so this repository cannot replay that run from a fresh clone. Start with the synthetic exercise below to see the packet and the questions a reviewer still has to answer. It tests the reading path, not the historical validation path.

It needs Python 3.9 or newer (standard library only) and no target or API key.

From `source/review-workbench`:

```sh
python3 test_review_workbench.py
demo_root=$(mktemp -d)
python3 demo_first_use.py --out-dir "$demo_root/review"
```

Use a **new** output directory; the script refuses to replace one. The script prints `"status": "DEMO_ONLY"` and two paths. Open `$demo_root/review/packet.demo.json` and `$demo_root/review/decision.demo.json`. The packet has one candidate, its report row, and hashes of an illustrative proof-of-concept (PoC) file and test file. The decision example is `NEEDS_MORE_EVIDENCE`: those files do not prove a weakness.

Both JSON files carry `demo_only: true` and a separate demo schema. The real `finalize_review.py` refuses the demo packet; it cannot turn this exercise into a human review receipt. Delete only the disposable directory you created when finished.

| What the exercise shows | What happens with a real run |
|---|---|
| One candidate and its artifact hashes | `prepare_review.py` binds a candidate to a completed results directory, its native validation record, and its raw log. |
| `PENDING_HUMAN` is a question, not a finding | The generated real packet remains pending until a named human reviews the evidence. |
| `NEEDS_MORE_EVIDENCE` is an illustrative response | A human fills every disposition and rationale in the real decision template, then the finalizer checks the exact packet hash. |
| `DEMO_ONLY`, `demo_only`, and the demo schema | These are deliberately **not** real packet/decision fields. Do not pass the demo JSON to `finalize_review.py`. |

For your own **authorized, completed** run, `prepare_review.py --help` shows the real input contract: a results directory, its matching native validation record, the raw event log, a run ID, and two new output paths. The optional reconciliation file preserves an earlier failed validation and binds a later correction; it is not a way to invent a pass. The resulting packet remains `PENDING_HUMAN`. A named human reviews the source trace, PoC, and observed exploit test; records a disposition and rationale for every candidate in the generated decision template; and only then runs `finalize_review.py --packet ... --decisions ... --out ...`. The finalizer does not authorize a production finding, deployment, recurrence, CI rule, publication, or a comparison between tools.

When no reconciliation file is supplied (the direct-PASS path), `prepare_review.py` checks that the validation record itself reports PASS and names the supplied results directory by path and digest, and the raw log by digest. It does not authenticate the producer of that record. Do not treat a successful local CLI run as independent validation or use these historical scripts against a real target without your own scope, containment, and source review.
