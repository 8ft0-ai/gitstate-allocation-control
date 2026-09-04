# Phase 2 stable operator — B2 preflight projection

B2 adds a non-authorising, capability-denied preflight path on top of the inert B1 manifest/governance/guard contracts. It does not add the successor execution capsule or activate the B1/B2 guard engine for live mutation. B2 validates a projected snapshot; it does not prove that private governance, App, state or environment facts remain current after that projection was published.

## Public carrier

Issue #28 is the dedicated public, non-secret projection/governance carrier. It is deliberately separate from issue #17, which remains the historical V1 execution-capsule/consumption surface.

The preflight record contract is `gitstate-preflight-projection/v1` with transport prefix:

`/gitstate-preflight-projection-v1 <canonical-json>`

The public invalidation contract is `gitstate-public-invalidation/v1` with transport prefix:

`/gitstate-public-invalidation-v1 <canonical-json>`

Both contracts are canonical one-line records, owner-bound, immutable by creation/update timestamp equality and bound by exact GitHub comment ID plus body SHA-256. Malformed reserved records, duplicate identities, wrong-owner records, edits, digest mismatch or ambiguous subject state fail closed.

A projection is evidence only. It carries `execution_authorised: false` and `workstream_e_authorised: false`; it cannot be parsed as a V1 execution capsule, cannot be consumed and cannot create a live authority object.

The projection embeds the exact canonical guarded B1 manifest so canonicalising the nested object reproduces the bound manifest SHA-256. It also carries the exact B1 governance source evidence needed for the pure B1 reducer to re-authenticate and re-parse governance semantics without granting the public workflow private-repository access. Projection construction must therefore apply the repository's public disclosure boundary before publication: governance source material containing credentials, personal/proprietary content, private repository names/URLs or other direct private-governance locators is not publishable.

### Private freshness boundary

The embedded governance and bound protocol/state/App/environment observations are a self-contained snapshot. The capability-denied B2 workflow cannot independently enumerate the private durable governance provider or reacquire private mutable boundaries. A later private revocation, supersession, consumption, state change, App-boundary change or environment-policy change can therefore make the projection stale without altering the projection itself.

B2 consequently never presents the pure B1 evaluator's positive result as current authority. A successful projected-snapshot evaluation emits `GITSTATE_PREFLIGHT_PROJECTION_VALID`, `projection_valid: true`, `private_freshness_proven: false`, and the qualified diagnostic `projected_snapshot_guard_code: PASS`. It never emits `GITSTATE_PREFLIGHT_PASS` or `guard_passed: true`. Negative evaluator outcomes and all independent public/read-only invalidators remain fail-closed as `GITSTATE_PREFLIGHT_BLOCKED`.

The absence of a public invalidation is not proof that no newer private lifecycle transition exists. B2 does not assume an atomic coupling between private governance mutation and public tombstone publication. Reusing the same projection for another bounded attempt-1 preflight may validate that same projected snapshot again, but can never establish current private freshness or current execution authority.

A later execution-capable slice must obtain current governance from the B1-conforming append-only/deletion-resistant authority and independently reacquire every mutable fact that becomes decision-critical at execution time. B2 deliberately does not widen its credential or mutation capability to solve that later integration problem.

## Public invalidation and deletion monotonicity

A public invalidation is a fail-closed tombstone only. It binds an exact projection and manifest subject and may additionally bind exact authority or manifest-approval identities. It carries no positive authority fields and cannot restore an invalidated object.

B2 queries GitHub's read-visible `CommentDeletedEvent` timeline for the dedicated carrier through the read-only GraphQL query surface. Any comment deletion on issue #28 permanently fails B2 preflight as `PUBLIC_CARRIER_DELETION_DETECTED`.

The mutable carrier is observed with a bounded stability check rather than an unsupported transactional-snapshot claim. B2 first requires a clean complete deletion-history read, then captures the complete paginated visible comment inventory twice. Each inventory is canonicalised over exact comment ID, body SHA-256, owner, creation timestamp and update timestamp. The two canonical inventory digests must be identical. A persistent addition, edit, projection replacement or invalidation appearing between the two scans therefore fails closed as `PUBLIC_CARRIER_CHANGED`. B2 then requires another clean complete deletion-history read before the second inventory may be used.

The accepted second inventory digest is emitted as `public_carrier_snapshot_sha256`. It identifies the exact visible carrier snapshot used for that B2 result. The two-scan check is deliberately described as bounded stability evidence, not as a linearizable or transactional GitHub snapshot. A change after the completed observation is outside that observation and is detected by a later preflight; B2 evidence remains non-authorising and is never reusable execution authority.

This carrier-wide deletion rule is deliberately stronger than subject-specific invalidation. B2 does not try to infer the content or identity of a deleted comment. Because issue #28 is a dedicated machine carrier, deletion means its visible comment inventory can no longer prove a complete monotonic history. Deleting a tombstone, projection or ordinary carrier comment therefore cannot make an older projection produce a valid B2 result again. Recovery from a deletion requires a new separately governed carrier/contract rather than reusing issue #28.

B3, if separately authorised and reviewed later, is responsible for enforcing this same public invalidation/deletion boundary or a stronger deletion-resistant durable-history boundary at execution-capsule discovery/consumption and live L1/L2 gates.

## Capability-denied preflight workflow

`operator_preflight` is now independent of the V1 execution-capsule jobs. Its workflow path:

- depends only on the credential-free contract-check job;
- has only `actions: read`, `contents: read` and `issues: read` GitHub-token permissions;
- does not enter the protected live environment;
- performs no capsule discovery or consumption;
- receives no allocator App private key, installation token, control/state mutation token or state-repository secret;
- accepts only the exact public projection comment ID and expected body SHA-256 as workflow inputs;
- uses a read-only GraphQL query only to enumerate GitHub-managed comment-deletion events for the dedicated public carrier;
- uses GitHub-managed workflow `run_number` ordinals only as read-only deletion/completeness evidence;
- runs the dedicated capability-denied `phase2.preflight_runtime` and stops after deterministic evidence output.

The historical `phase2.operator_runtime preflight` command is retired and fails closed as `OPERATOR_PREFLIGHT_PROJECTION_REQUIRED`. The earlier executable path in `phase2.preflight_projection` is also retired: its `run_preflight` and legacy suffix validator fail closed as `PREFLIGHT_RUNTIME_REQUIRED`. `phase2.preflight_runtime` is the sole B2 executable preflight implementation. The V1 live execution route still uses the unchanged capsule discovery/consumption and existing credential/revocation stack.

## Observation and guard model

The preflight projection supplies explicitly bound, non-secret observation evidence for protocol/state/App/environment facts that the capability-denied workflow cannot safely acquire itself. The workflow independently reacquires the key-free decision-critical observations available through its read-only GitHub credential:

- protected control commit/tree identity;
- workflow and bounded module blob identities;
- complete public V1 operator history;
- two matching complete visible preflight projection/invalidation inventories plus the exact accepted carrier snapshot digest;
- GitHub-managed comment-deletion history for the dedicated carrier, with any deletion permanently fail-closed;
- complete workflow-dispatch history through the manifest baseline plus explicitly bound post-baseline preflight observations;
- workflow-run ordinal continuity from the manifest baseline through the current preflight, so deletion of a completed post-baseline run cannot restore a projection-valid result;
- the exact repository-versioned Workstream-D execution-variable identity plus its unprotected job-context absence observation.

The execution-variable identity is not projection-selectable. B2 requires both the manifest environment field and the bound observation to name exactly `PHASE2_WORKSTREAM_D_EXECUTION_ENABLED`. The job-context absence check is only an input to projected-snapshot validation; because B2 does not enter `phase-2-allocator`, it is not evidence of current protected-environment freshness and cannot turn `private_freshness_proven` true.

The resulting typed `GuardObservation` is evaluated by the same pure `phase2.operator_guard.evaluate_guards` implementation introduced in B1. The guard receives no GitHub API, token-mint, ref-update, workflow-dispatch or scenario-execution capability. Its result describes the supplied projected snapshot only; B2 qualifies that result before exposing evidence and does not expose an ordinary B1 guard-PASS contract.

A manifest-bound owner observation remains subject to the B1 `valid_through` freshness rule. A matching caller-supplied validity flag cannot override expiry. That bound deadline can make a projection fail, but passing the deadline check does not prove that other private mutable facts remain current.

## Workflow-history reconciliation

The guarded manifest binds the complete workflow history through its construction baseline. B2 reconstructs all `workflow_dispatch` records through that baseline, including every historical attempt of any rerun, and requires the resulting canonical B1 workflow-history baseline to match the manifest exactly.

GitHub's per-workflow `run_number` is a separate B2 completeness signal rather than part of the B1 canonical digest. The baseline's latest surviving bound run provides the ordinal anchor; an empty baseline anchors at zero. From that anchor through the current preflight run, every ordinal must be present exactly once. Because a rerun increments `run_attempt` without consuming another `run_number`, historical rerun reconstruction remains governed by the existing B1 attempt digest while deletion of an entire completed run leaves a permanent ordinal gap. Missing, duplicate or malformed ordinals are `WORKFLOW_HISTORY_CHANGED`.

After the bound baseline, B2 permits one or more non-authorising `operator_preflight` attempt-1 observations only when every such run is on the exact protected control SHA and its immutable Actions display title binds the same preflight-projection comment ID, projection body SHA-256 and manifest SHA-256. The current run must be present in that bounded suffix. A further preflight is therefore another independently identified observation of the projected snapshot, never reusable authority or proof that private facts remain fresh.

Any historical prefix change, live rerun, post-baseline rerun, unrelated dispatch, deleted workflow-run gap, mismatched trusted SHA, mismatched projection/manifest identity, duplicate run identity or malformed attempt history is `WORKFLOW_HISTORY_CHANGED`/fail-closed evidence.

## Evidence

A successful B2 preflight emits deterministic projection-validation evidence including run ID/attempt, protected control SHA, projection comment/body identity, manifest SHA-256, `public_carrier_snapshot_sha256` and the qualified projected-snapshot guard diagnostic. Every successful record states:

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

B2 does not emit `GITSTATE_PREFLIGHT_PASS`, `guard_passed`, `guard_code` or `guard_category`. Those unqualified names could be misread as current-authority evidence and are deliberately absent from the executable B2 evidence contract.

A carrier deletion, unstable carrier inventory, workflow-history discontinuity, public invalidation or negative projected-snapshot guard result produces blocked evidence. All blocked command output remains non-authorising and emits no credential material.

`GITSTATE_PREFLIGHT_PROJECTION_VALID` means only that the exact public projection, a bounded-stable visible carrier inventory and the independently reacquired public/read-only facts satisfy B2's consistency checks. It is not evidence that current private authority exists, is unconsumed, is unrevoked or that current private App/state/environment facts still match the projection.

## B2 boundary

B2 does not:

- add or activate a successor execution capsule;
- modify the existing V1 live capsule/consumption semantics;
- provide an allocator App key to preflight;
- read the private durable governance provider;
- prove current private governance/App/state/environment freshness;
- mint an installation/control/state token in preflight;
- dispatch a live workflow as implementation validation;
- enter the protected environment;
- mutate/recover retained state;
- authorise Workstream E or scenario 15.

Successor execution-capsule and live L1/L2 integration remain a separately governed B3 slice requiring a new implementation authority and fresh substantive review.
