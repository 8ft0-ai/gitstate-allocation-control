# Phase 2 stable operator — B2 preflight projection

B2 adds a non-authorising, capability-denied preflight path on top of the inert B1 manifest/governance/guard contracts. It does not add a successor execution capsule or activate B1/B2 authority for live mutation.

A successful B2 result means only that an exact public projection, a deletion-resistant protected-main carrier ledger, a bounded-stable current public carrier view and the independently reacquired read-only facts satisfy the B2 consistency checks. It does not prove that private governance, App, state or environment facts remain current.

## Public carrier and durable history

Issue #28 remains the dedicated public, non-secret projection/invalidation presentation surface. It is deliberately separate from issue #17, which remains the historical V1 execution-capsule/consumption surface.

The issue conversation must remain locked. Every production carrier scan requires `locked: true`; an unlocked carrier fails closed as `PUBLIC_CARRIER_NOT_LOCKED`.

Current issue visibility is not used as the sole memory of what has previously existed. The deletion-resistant historical floor is:

`policy/preflight-carrier-ledger.json`

The ledger contract is:

`gitstate-public-carrier-ledger/v1`

Its baseline is the merged B1 protected-main commit:

`2001449abb567deff097e76e228a5af9ebd0743d`

The file is introduced after that baseline with an empty record set. From then on, every protected-main first-parent state must either leave the ledger byte-canonically unchanged or append exactly one chained record. Removal, mutation, reordering, replacement, multi-record jumps, deletion of the ledger, failure to reach the pinned B1 baseline, or a malformed chain is fail-closed evidence.

This uses the already authoritative protected `main` history as the durable memory. A separate unprotected carrier branch is deliberately not used: a rewindable ref would not provide the monotonic proof required by B2.

Production brackets every potentially positive B2 evaluation with two protected-main fences. Before trusting the ledger, the currently dispatched `GITHUB_SHA` must be the current head of GitHub-reported protected `main`. Immediately before any `projection_valid: true` evidence is constructed or emitted, production re-reads `main`, again requires `protected: true`, and requires the head to remain exactly the dispatched SHA.

The final protected-main read is the positive-evidence linearisation point. If `main` advances between the entry and exit fences, including because a durable invalidation append reaches protected main after the ledger was first validated, the positive path fails closed as `PUBLIC_CARRIER_LEDGER_MAIN_MOVED` and may be dispatched again from the new protected head. Already-negative outcomes do not rely on this exit fence because they cannot restore or create eligibility.

## Ledger records

Every ledger record has a strictly increasing sequence, an opaque record ID, an exact body SHA-256, exact manifest SHA-256, the previous record SHA-256 and a SHA-256 over the canonical record payload. The first record chains from 64 zeroes.

A projection ledger record additionally binds the exact public projection comment ID. B2 therefore cannot accept a deleted projection followed by an identical repost under a new comment identity.

An invalidation ledger record binds the exact projection comment ID, projection body SHA-256 and manifest SHA-256 that it invalidates. Once such a record appears in protected-main history, preflight permanently fails that subject as `PUBLIC_CARRIER_LEDGER_INVALIDATED`, even if the public invalidation comment is later absent and GitHub has not yet exposed a corresponding `CommentDeletedEvent`.

The ledger is fail-closed authority only. It never grants execution authority.

### Publication order and exact control anchor

Projection publication is deliberately two-step:

1. post the canonical projection record to locked issue #28 while its embedded B1 manifest binds the exact protected-main executor commit/tree used to construct the projection;
2. append its exact comment ID/body/manifest binding to the protected-main ledger through the normal reviewed main-change process.

Before step 2 is merged, B2 fails as `PUBLIC_CARRIER_LEDGER_PROJECTION_NOT_BOUND`.

The second step necessarily advances protected `main`: GitHub does not assign the public comment ID until step 1 has happened, while the durable ledger record must bind that exact comment identity and body digest. B2 therefore does not pretend that the post-publication ledger commit is the manifest's original B1 executor commit.

Instead, production permits the current dispatched protected-main SHA to differ from the manifest's projected executor SHA only through a narrowly proved carrier-ledger bridge. The current SHA must be a first-parent descendant of the projected executor SHA, and every intervening commit must change exactly `policy/preflight-carrier-ledger.json` with no other file change. A code, workflow, module, policy or unrelated repository change fails closed as `PUBLIC_CARRIER_LEDGER_CONTROL_DRIFT`; an unreachable or ambiguous projected anchor also fails closed.

After that proof, the pure B1 guard reacquires control tree, workflow and module identities at the manifest's exact projected executor SHA. The current dispatched `GITHUB_SHA` remains authoritative for the current workflow run, workflow-history reconciliation and current protected-main ledger state. This is not a general allowance for protected-main drift: it exists only to bridge the unavoidable comment-first ledger publication step without weakening the exact B1 control identity.

Invalidation publication reverses the safety order:

1. append the invalidation subject/body binding to protected main;
2. then publish the corresponding public invalidation record to issue #28.

The protected-main ledger makes the invalidation effective immediately after step 1. A failure or delay in publishing the public mirror therefore cannot restore projection validity. The exit protected-main fence ensures that an in-flight run which evaluated the pre-invalidation ledger cannot emit positive evidence after that append becomes current protected main.

Any non-ledger protected-main change after a projection's executor anchor invalidates that projection for B2 and requires a newly constructed projection rather than silently rebasing the old projected authority.

## Current carrier observation

Production still reads issue #28 through one GitHub GraphQL `Issue.timelineItems` connection filtered to `ISSUE_COMMENT` and `COMMENT_DELETED_EVENT`.

The same connection supplies visible projection/invalidation comments and GitHub-managed deletion events. Every page must report `locked: true` and well-formed connection metadata. Counts, update metadata and cursor progression must remain internally consistent through a scan.

Any visible `CommentDeletedEvent` fails B2 as `PUBLIC_CARRIER_DELETION_DETECTED`.

B2 performs two complete current-carrier reads and requires identical canonical carrier-history digests. This is bounded current-observation stability only. It is explicitly not treated as a transaction, a globally linearizable snapshot or the durable historical floor.

The exact review failure fixed by the protected-main ledger is the case where both unified timeline scans have already omitted a deleted invalidation while the deletion event is not yet visible. The two scans may agree, but the protected-main ledger still contains the invalidation and prevents `GITSTATE_PREFLIGHT_PROJECTION_VALID`.

## Projection and invalidation contracts

A projection record on issue #28 uses exactly one line:

`/gitstate-preflight-projection-v1 <canonical-json>`

Its canonical payload contract is:

`gitstate-preflight-projection/v1`

A public invalidation uses exactly one line:

`/gitstate-public-invalidation-v1 <canonical-json>`

Its payload contract is:

`gitstate-public-invalidation/v1`

Both are owner-bound, canonical and immutable by exact creation/update timestamp equality. Malformed reserved records, duplicate identities, wrong-owner records, edits, digest mismatches or ambiguous subject state fail closed.

Every projection carries:

- `execution_authorised: false`;
- `workstream_e_authorised: false`.

A projection cannot be parsed as a V1 execution capsule, cannot be consumed and cannot create a live authority object.

## Private freshness boundary

The projection embeds a canonical guarded B1 manifest plus the exact governance source evidence and bound protocol/state/App/environment observations needed for deterministic B1 guard evaluation.

Those are projected facts. The B2 job cannot independently reacquire private durable governance or other private mutable boundaries.

A positive projected result is therefore always qualified as:

- `status: GITSTATE_PREFLIGHT_PROJECTION_VALID`;
- `projection_valid: true`;
- `private_freshness_proven: false`;
- `projected_snapshot_guard_code: PASS`;
- `execution_authorised: false`;
- `credential_material_emitted: false`;
- `control_state_tokens_minted: 0`;
- `canonical_state_mutated: false`;
- `workstream_d_scenarios_executed: 0`;
- `workstream_e_authorised: false`.

B2 never emits ordinary `GITSTATE_PREFLIGHT_PASS` or `guard_passed: true`.

A later private revocation, supersession, consumption, state change, App-boundary change or environment-policy change can make the projection stale without changing the projection. B2 does not claim otherwise.

## Workflow capability boundary

`operator_preflight` remains independent of the V1 execution-capsule path.

It has only:

- `actions: read`;
- `contents: read`;
- `issues: read`.

It does not enter `phase-2-allocator`, receive the allocator App private key, obtain installation/control/state tokens, access a state-repository secret, consume an execution capsule or receive any mutation-capability provider.

The protected-main ledger and control-anchor checks require only the existing read-only GitHub token.

The historical `phase2.operator_runtime preflight` command remains retired. The earlier executable path in `phase2.preflight_projection` also remains retired. `phase2.preflight_runtime` is still the sole workflow entry point; it wraps the previously reviewed B2 runtime with the protected-main carrier-ledger fence and the ledger-only exact-control-anchor bridge.

## Workflow-history reconciliation

The guarded manifest still binds complete workflow history through its construction baseline.

B2 reconstructs every historical `workflow_dispatch` attempt through that baseline and requires the canonical B1 workflow-history baseline to match exactly. It additionally requires GitHub-managed workflow `run_number` continuity through the current attempt-1 preflight.

A missing run, rerun, duplicate ordinal, unrelated post-baseline dispatch, wrong current protected control SHA or mismatched projection/manifest identity remains `WORKFLOW_HISTORY_CHANGED`.

The carrier ledger and exact-control-anchor bridge do not weaken or replace those controls.

## Public disclosure boundary

Only non-sensitive synthetic identifiers and approved opaque bindings may appear in this public repository, issue #28, the ledger, workflow inputs, logs and artefacts.

Do not publish credentials, tokens, personal data, proprietary task content, private repository identities or direct private-governance locators.

Ledger records contain only public comment identities, opaque record IDs and hashes/bindings already permitted by the B2 public boundary.

## B2 boundary

B2 does not:

- add or activate a successor execution capsule;
- modify the existing V1 live capsule/consumption semantics;
- provide an allocator App key to preflight;
- read the private durable governance provider;
- prove current private governance/App/state/environment freshness;
- mint an installation/control/state token in preflight;
- dispatch a live scenario as implementation validation;
- enter the protected environment;
- mutate or recover retained canonical state;
- authorise Workstream E;
- add scenario 15.

Successor execution-capsule and live L1/L2 integration remain separately governed later work.
