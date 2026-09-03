# Phase 2 stable operator contracts — B1

This document describes the inert B1 contract surface for the governed stable-operator redesign. B1 introduces only repository-versioned data contracts, canonical history models and a pure semantic guard evaluator. It does not activate a successor execution path, change the protected workflow, dispatch a workflow, access credentials, mint tokens, mutate state or authorise Workstream E.

## Execution manifest

The private execution manifest contract is `gitstate-live-execution-manifest/v1`.

A manifest is a canonical UTF-8 JSON object. Parsing is fail-closed: exact schema keys only; duplicate keys are rejected; floats, non-finite numbers and null are rejected; object keys are lexicographically sorted; separators are `,` and `:` with no insignificant whitespace; there is no trailing newline; and SHA-256 is calculated over those exact canonical UTF-8 bytes. A non-canonical representation is rejected rather than silently normalised.

The manifest binds the decision-critical execution inputs without carrying secrets: contract, operation and governing issue; exact executor repository/commit/tree/workflow/module identities; protocol identity; exact proposal/readiness/authority comment and body bindings; state baseline; operator/workflow history baselines; allocator App boundary; any bounded owner-observation dependency; protected-environment policy; exact execution-enable variable absence expectation; `single_use: true`; and `workstream_e_authorised: false`.

The parsed manifest is a deeply immutable value after digest verification. Mapping containers are read-only and array containers are tuples, so later caller code cannot change decision-critical semantics while retaining the previously verified digest.

## Structured governance

The private governance machine-record contract is `gitstate-execution-governance/v1`.

A governing comment may contain human rationale but has exactly one reserved machine-record line:

`/gitstate-governance-v1 <canonical-json>`

Supported record types are `proposal`, `readiness`, `authority`, `manifest_approval`, `supersession`, `revocation`, `consumption` and `terminal`.

Every parsed machine record is owner-authenticated, timestamp-valid, immutable by created/updated timestamp equality, and bound by GitHub comment ID plus exact comment-body SHA-256. Duplicate comment IDs, duplicate record IDs, malformed reserved records and body-digest mismatches fail closed. Parsed governance payloads are deeply immutable after validation.

### Lineage and manifest scopes

Proposal, readiness and authority exist before the manifest, so they bind an immutable lineage ID plus exact prior record/comment-body bindings. Post-manifest records additionally bind a manifest SHA-256.

Authority lifecycle is deliberately not scoped away by manifest replacement. A typed consumption, revocation or supersession that targets a bound proposal/readiness/authority remains effective for any successor manifest that attempts to reuse the same lineage authority. In particular, a one-use authority consumed under manifest A cannot become usable again merely because manifest B has a different digest.

Manifest approvals remain manifest-scoped. Revocation of an approval for manifest A does not by itself invalidate a distinct approval for manifest B. Live-stage evaluation requires the exact current manifest approval bound to the exact current authority comment/body identity.

Current-manifest lifecycle records cannot be schema-valid no-ops. Revocation/supersession targets must be non-empty, resolvable prior records. Consumption must target exactly the active authority. Duplicate consumption for one authority fails governance validation.

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

## Pure semantic guard evaluator

`phase2.operator_guard` accepts an immutable parsed manifest plus a typed observation object and returns `PASS` or one typed failure. It imports no GitHub API, credential, token-mint, workflow-dispatch, ref-update or Workstream-D live execution provider.

A complete observation is shape-validated before semantic comparison. It binds an explicit timezone-aware UTC evaluation instant plus exact operation, control repository/commit/tree/workflow/module identities, protocol/state identities, operator/workflow baselines, App boundary, environment policy and exact execution-enable variable name/absence.

When an owner observation is required, the common evaluator owns its freshness decision. Caller-supplied validity cannot override the manifest's `valid_through` boundary; `evaluated_at >= valid_through` produces `APP_BOUNDARY_CHANGED`.

Authority/security failures are `GOVERNANCE_RECORD_INVALID`, `GOVERNANCE_AMBIGUOUS`, `GOVERNANCE_SUPERSEDED`, `AUTHORITY_NOT_GRANTED`, `AUTHORITY_CONSUMED` and `WORKSTREAM_E_NOT_AUTHORISED`.

Mutable invalidators are `CONTROL_IDENTITY_CHANGED`, `WORKFLOW_IDENTITY_CHANGED`, `PROTOCOL_IDENTITY_CHANGED`, `STATE_BASELINE_CHANGED`, `OPERATOR_HISTORY_CHANGED`, `WORKFLOW_HISTORY_CHANGED`, `APP_BOUNDARY_CHANGED`, `ENVIRONMENT_BOUNDARY_CHANGED` and `EXECUTION_ENABLEMENT_CHANGED`.

Observation-incomplete failures are `READ_EVIDENCE_UNAVAILABLE`, `READ_EVIDENCE_RATE_LIMITED` and `READ_EVIDENCE_AMBIGUOUS`.

Implementation-defect failures are `MANIFEST_SCHEMA_UNSUPPORTED`, `OBSERVATION_SHAPE_UNSUPPORTED` and `GUARD_EVALUATOR_DEFECT`.

Every non-PASS result is diagnostic only. Nothing in B1 authorises automatic refresh, repair, redispatch, authority reuse or mutation.

## Activation boundary

B1 is intentionally inert. It does not modify the protected workflow, the existing V1 capsule/runtime implementation, credential or App-token providers, Workstream-D live/recovery helpers, public operator-history state, environment/App/repository settings or retained state. Later integration slices remain separately governed and require separate fresh review before activation.

No B1 result creates merge, live execution, workflow-dispatch, credential, state-mutation, recovery or Workstream-E authority.
