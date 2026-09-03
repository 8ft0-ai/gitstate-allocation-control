# Phase 2 stable operator contracts — B1

This document describes the inert B1 contract surface for the governed stable-operator redesign. B1 introduces only repository-versioned data contracts, canonical history models and pure semantic guard/reducer code. It does not activate a successor execution path, change the protected workflow, dispatch a workflow, access credentials, mint tokens, mutate state or authorise Workstream E.

## Execution manifest

The private execution manifest contract is `gitstate-live-execution-manifest/v1`.

The guardable B1 representation extends the core execution-manifest payload with one required `governance_history` baseline. `phase2.governance_state.parse_guarded_execution_manifest` validates the complete canonical object, validates the unchanged core manifest through `phase2.operator_manifest`, and calculates the manifest SHA-256 over the complete object including that governance-history baseline. The baseline is therefore part of the exact manifest identity used by post-manifest governance records.

A manifest is a canonical UTF-8 JSON object. Parsing is fail-closed: exact schema keys only; duplicate keys are rejected; floats, non-finite numbers and null are rejected; object keys are lexicographically sorted; separators are `,` and `:` with no insignificant whitespace; there is no trailing newline; and SHA-256 is calculated over those exact canonical UTF-8 bytes. A non-canonical representation is rejected rather than silently normalised.

The manifest binds the decision-critical execution inputs without carrying secrets: contract, operation and governing issue; exact executor repository/commit/tree/workflow/module identities; protocol identity; exact proposal/readiness/authority comment and body bindings; the canonical governance-history prefix through which the manifest was created; state baseline; operator/workflow history baselines; allocator App boundary; any bounded owner-observation dependency; protected-environment policy; exact execution-enable variable absence expectation; `single_use: true`; and `workstream_e_authorised: false`.

The parsed manifest is a deeply immutable value after digest verification. Mapping containers are read-only and array containers are tuples, so later caller code cannot change decision-critical semantics while retaining the previously verified digest.

## Structured governance

The private governance machine-record contract is `gitstate-execution-governance/v1`.

A governing comment may contain human rationale but has exactly one reserved machine-record line:

`/gitstate-governance-v1 <canonical-json>`

Supported record types are `proposal`, `readiness`, `authority`, `manifest_approval`, `supersession`, `revocation`, `consumption` and `terminal`.

Every parsed machine record is owner-authenticated, timestamp-valid, immutable by created/updated timestamp equality, and bound by GitHub comment ID plus exact comment-body SHA-256. Duplicate comment IDs, duplicate record IDs, malformed reserved records and body-digest mismatches fail closed. Parsed governance payloads are deeply immutable after validation.

### Durable governance history

GitHub comments are governance transport and evidence; they are not by themselves the durable authority for irreversible lifecycle state. A fresh enumeration of currently visible comments is therefore not a conforming source for B1 live integration.

The common guard consumes a `GovernanceHistory` value. It contains the exact guarded-manifest SHA-256 to which the snapshot applies, a canonical `HistoryBaseline` over the complete supplied governance-record sequence, and the immutable ordered governance records used by the reducer.

The canonical history form is:

`<comment-id>\t<record-id>\t<record-type>\t<body-sha256>\n`

The SHA-256 baseline covers the complete concatenated UTF-8 sequence including the final newline. The guarded manifest carries the required prefix baseline. Evaluation recomputes both the complete observation baseline and the prefix ending at the manifest's `through_id`; the observed prefix must exactly equal the baseline embedded in the manifest.

This closes the successor-manifest deletion case at the manifest boundary. If authority was consumed or revoked before successor manifest B was created, B's digest commits to a governance prefix containing that irreversible transition. Even a newly recomputed, internally self-consistent shorter history fails `GOVERNANCE_HISTORY_CHANGED` because its prefix cannot reproduce B's embedded baseline.

B1 deliberately does not implement the live history provider. A later separately reviewed integration slice must obtain `GovernanceHistory` from the governed private append-only/deletion-resistant authority and must retain irreversible transitions created after the current manifest as well. The provider may extend history but must never reconstruct a shorter authoritative history from currently visible comments. This is a required trust-boundary property of later activation, not an optional caller convention.

### Lineage and manifest scopes

Proposal, readiness and authority exist before the manifest, so they bind an immutable lineage ID plus exact prior record/comment-body bindings. Post-manifest records bind the exact guarded-manifest SHA-256, which includes its governance-history prefix baseline.

Authority lifecycle is deliberately not scoped away by manifest replacement. A typed consumption, revocation or supersession that targets a bound proposal/readiness/authority remains effective for any successor manifest that attempts to reuse the same lineage authority. In particular, a one-use authority consumed under manifest A cannot become usable again merely because manifest B has a different digest.

Manifest approvals remain manifest-scoped. Revocation of an approval for manifest A does not by itself invalidate a distinct approval for manifest B.

Approval selection is not a caller input. The governance reducer derives the effective approval from durable history. At a live stage, zero active approvals or one active `rejected` approval produces `AUTHORITY_NOT_GRANTED`; exactly one active `approved` approval is usable; more than one active approval is `GOVERNANCE_AMBIGUOUS`. Replacing an approval therefore requires an explicit prior revocation or supersession; implicit last-comment-wins semantics are forbidden.

Lifecycle target provenance is exact rather than subset-based. Revocation and supersession records must bind every targeted prior record by exact comment ID and body SHA-256, with no missing or additional binding. Consumption must target exactly the active authority and carry exactly that authority's comment/body binding. Under-bound lifecycle records are `GOVERNANCE_RECORD_INVALID`.

A terminal record is also semantically constrained rather than merely parsed: it must target the exact preceding consumption record for the same manifest, include the exact consumption comment/body binding, occur after that consumption, and carry the same run ID and run attempt. Orphan, duplicate, forward-bound or run-mismatched terminal records are `GOVERNANCE_RECORD_INVALID`.

## Historical V1 operator history

Existing `gitstate-operator/v1` capsule and `gitstate-consumption/v1` comments remain historical inputs. B1 does not rewrite the active V1 execution path.

Historical validation preserves the active V1 static acceptance boundary, including owner identity, exact fields, canonical JSON, immutable comment timestamps, provenance IDs/digests, trusted SHA fields, one-use requirement, bounded capsule lifetime, Workstream-E exclusion and the capsule projection-time skew rule. A capsule comment may be at most one minute before the capsule's declared `created_at`; comments later than `expires_at` are rejected. Historical expiry relative to the present clock is intentionally not re-evaluated.

A complete closed V1 history is canonicalised as:

`<comment-id>\t<record-kind>\t<body-sha256>\n`

The SHA-256 baseline covers the complete concatenated UTF-8 sequence including the final newline. Validation rejects malformed or edited reserved records, duplicate capsule IDs, unconsumed capsules, orphan/duplicate consumption, identity mismatches, live reruns or duplicate run/attempt identities, and Workstream-E-bearing records. A requested history prefix must itself be closed.

## Workflow-history baseline

B1 defines deterministic workflow-dispatch identity using:

`<run-id>\t<run-attempt>\t<trusted-sha>\t<operation>\n`

Terminal conclusion is intentionally excluded from this baseline. If terminal evidence becomes decision-critical, it must be modelled explicitly rather than inherited as a stale historical literal.

## Pure governance reducer and semantic guard

`phase2.governance_state` owns the guarded-manifest parser, canonical governance-history model and the single pure reducer for governance lifecycle semantics. Given an exact guarded manifest plus its manifest-bound durable `GovernanceHistory`, it validates the embedded history prefix, causal lineage, lifecycle targets, consumption/terminal structure and active authority, then derives a `GovernanceState` including the effective manifest-approval status.

`phase2.operator_guard` accepts the immutable guarded manifest plus a typed observation object and returns `PASS` or one typed failure. It imports no GitHub API, credential, token-mint, workflow-dispatch, ref-update or Workstream-D live execution provider. The guard does not accept a caller-selected manifest approval.

A complete observation is shape-validated before semantic comparison. It binds an explicit timezone-aware UTC evaluation instant plus exact operation, control repository/commit/tree/workflow/module identities, protocol/state identities, operator/workflow baselines, App boundary, environment policy, exact execution-enable variable name/absence and the manifest-bound durable governance history.

When an owner observation is required, the common evaluator owns its freshness decision. Caller-supplied validity cannot override the manifest's `valid_through` boundary; `evaluated_at >= valid_through` produces `APP_BOUNDARY_CHANGED`.

Authority/security failures are `GOVERNANCE_HISTORY_CHANGED`, `GOVERNANCE_RECORD_INVALID`, `GOVERNANCE_AMBIGUOUS`, `GOVERNANCE_SUPERSEDED`, `AUTHORITY_NOT_GRANTED`, `AUTHORITY_CONSUMED` and `WORKSTREAM_E_NOT_AUTHORISED`.

Mutable invalidators are `CONTROL_IDENTITY_CHANGED`, `WORKFLOW_IDENTITY_CHANGED`, `PROTOCOL_IDENTITY_CHANGED`, `STATE_BASELINE_CHANGED`, `OPERATOR_HISTORY_CHANGED`, `WORKFLOW_HISTORY_CHANGED`, `APP_BOUNDARY_CHANGED`, `ENVIRONMENT_BOUNDARY_CHANGED` and `EXECUTION_ENABLEMENT_CHANGED`.

Observation-incomplete failures are `READ_EVIDENCE_UNAVAILABLE`, `READ_EVIDENCE_RATE_LIMITED` and `READ_EVIDENCE_AMBIGUOUS`.

Implementation-defect failures are `MANIFEST_SCHEMA_UNSUPPORTED`, `OBSERVATION_SHAPE_UNSUPPORTED` and `GUARD_EVALUATOR_DEFECT`.

Every non-PASS result is diagnostic only. Nothing in B1 authorises automatic refresh, repair, redispatch, authority reuse or mutation.

## Activation boundary

B1 is intentionally inert. It does not modify the protected workflow, the existing V1 capsule/runtime implementation, credential or App-token providers, Workstream-D live/recovery helpers, public operator-history state, environment/App/repository settings or retained state. The durable governance-history provider and any successor workflow integration remain separately governed later slices and require separate fresh review before activation.

No B1 result creates merge, live execution, workflow-dispatch, credential, state-mutation, recovery or Workstream-E authority.
