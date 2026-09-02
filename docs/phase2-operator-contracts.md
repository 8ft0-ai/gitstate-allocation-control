# Phase 2 stable operator contracts — B1

This document describes the inert B1 contract surface authorised by Gitstate Lab issue #40. B1 introduces only repository-versioned data contracts, canonical history models and a pure semantic guard evaluator. It does not activate a successor execution path, change `.github/workflows/phase2-adversarial.yml`, dispatch a workflow, access credentials, mint tokens, mutate state, or authorise Workstream E.

## Execution manifest

The private execution manifest contract is:

`gitstate-live-execution-manifest/v1`

A manifest is a canonical UTF-8 JSON object. Parsing is fail-closed:

- exact schema keys only;
- duplicate JSON keys are rejected;
- floats, non-finite numbers and null values are rejected;
- object keys are lexicographically sorted in the canonical representation;
- separators are `,` and `:` with no insignificant whitespace;
- no trailing newline is part of the canonical byte string;
- SHA-256 is calculated over those exact canonical UTF-8 bytes;
- a non-canonical source representation is rejected rather than silently normalised.

The manifest binds the decision-critical execution inputs without carrying secrets:

- contract, operation and governing issue;
- exact executor repository, commit, tree, workflow blob and ordered module blob set;
- protocol identity;
- exact proposal, readiness and authority comment identities plus body SHA-256 bindings;
- state-baseline commit and digest;
- canonical operator-history and workflow-history baselines;
- allocator App identity, installation, repository-selection, selected repository IDs and permission-profile digest;
- any explicitly bounded owner-observation dependency and its RFC-3339 freshness boundary;
- protected-environment identity/policy and exact execution-enable variable absence expectation;
- `single_use: true`;
- `workstream_e_authorised: false`.

The manifest deliberately does not contain its later `manifest_approval` identity. Approval is a post-manifest governance record that targets the immutable manifest digest.

## Structured governance

The private governance machine-record contract is:

`gitstate-execution-governance/v1`

A governing comment may contain human rationale but has exactly one reserved machine-record line:

`/gitstate-governance-v1 <canonical-json>`

The supported record types are:

- `proposal`;
- `readiness`;
- `authority`;
- `manifest_approval`;
- `supersession`;
- `revocation`;
- `consumption`;
- `terminal`.

Every parsed machine record is owner-authenticated, timestamp-valid, immutable by created/updated timestamp equality, and bound by GitHub comment ID plus exact comment-body SHA-256. Duplicate comment IDs, duplicate record IDs, duplicate reserved lines, malformed reserved records and body-digest mismatches fail closed. Subject record IDs and comment bindings are deterministically ordered and unique. Ordinary comments carry no machine semantics.

### Subject identity and the pre-manifest boundary

Proposal, readiness and authority necessarily exist before the manifest can bind their exact comment-body digests. Requiring those earlier records to contain the later manifest SHA-256 would create a digest cycle:

`manifest digest -> governance body digest -> manifest digest`

B1 therefore models the accepted design's “normally manifest SHA-256” subject rule as two phases:

- pre-manifest `proposal`, `readiness` and `authority` records bind an immutable opaque `lineage_id`, prior typed record IDs and exact prior comment bindings;
- post-manifest records bind the exact `manifest_sha256`, plus the relevant typed record IDs/comment bindings.

The pure evaluator requires the manifest-bound proposal/readiness/authority comments to resolve to one consistent lineage and requires readiness/authority to bind the exact prior comment bodies, not merely their record IDs. It never infers authority from prose, numerical latest-comment position or unrelated later comments.

A later typed `revocation` or `supersession` targeting the bound proposal, readiness or authority invalidates the lineage. A matching typed `consumption` invalidates one-use authority. More than one simultaneously active, correctly bound authority on the same lineage is `GOVERNANCE_AMBIGUOUS`.

Manifest-scoped lifecycle records are fail-closed as a complete semantic unit rather than accepted as inert syntax. A `manifest_approval` must name the exact bound authority and its exact comment/body binding. A `revocation` or `supersession` must contain at least one resolvable prior target from the bound proposal/readiness/authority lineage or the manifest's approval records; an empty, unknown, unrelated or forward target is `GOVERNANCE_RECORD_INVALID`. A `consumption` must target exactly the bound active authority, and more than one matching consumption is invalid. Optional lifecycle comment bindings may only refer to the records named by that lifecycle subject. A lifecycle record for the current manifest is therefore either semantically valid and effective, or it fails governance validation; it is never silently ignored because its subject is malformed.

A live-stage `manifest_approval` must target the exact manifest digest, name the bound authority record and include the exact authority comment/body binding. B1 represents the later public-invalidation binding as a typed governance detail but does not implement the public projection/invalidation transport. That transport belongs to B2/B3.

## Historical V1 operator history

Existing `gitstate-operator/v1` capsule and `gitstate-consumption/v1` comments remain historical inputs. B1 does not rewrite or reinterpret the active V1 execution path.

Before a V1 record is admitted to canonical history, B1 statically validates its historical contract: exact fields, canonical JSON, owner identity, comment immutability/timestamps, V1 governance contract, opaque IDs/digests, trusted SHA fields, single-use requirement, bounded capsule lifetime and Workstream-E exclusion. Consumption records additionally validate capsule binding, run identity/attempt, trusted SHA, operation and consumption timestamp.

For a complete **closed** V1 history ordered by numeric comment ID, canonical history is:

`<comment-id>\t<record-kind>\t<body-sha256>\n`

The SHA-256 baseline covers the complete concatenated UTF-8 sequence including the final newline. Validation rejects:

- malformed or edited reserved records;
- duplicate capsule IDs;
- unconsumed capsules;
- orphan consumptions;
- more than one consumption for a capsule;
- capsule/comment/body/trusted-SHA/operation mismatches;
- live reruns or duplicate run/attempt identities;
- Workstream-E-bearing records.

A requested history prefix must itself be closed. A prefix ending after a capsule but before its matching consumption is not a valid baseline merely because a later full history is closed.

The resulting baseline is represented by `(through_id, history_sha256)` for later preflight/live comparison.

## Workflow-history baseline

B1 defines a deterministic workflow-dispatch identity projection using:

`<run-id>\t<run-attempt>\t<trusted-sha>\t<operation>\n`

Terminal conclusion is intentionally excluded from this baseline. The v1-v4 evidence showed that stale inherited interpretation of a prior run's terminal conclusion can block execution even when that conclusion is not part of the authority/security contract. Dispatch identity, attempt, trusted SHA and operation remain bound; any future terminal evidence requirement must be modelled explicitly rather than smuggled in as a historical literal.

B2 will define the bounded preflight-run suffix semantics. B3 will define the exact live attempt suffix. B1 only provides the pure baseline representation.

## Pure semantic guard evaluator

`phase2.operator_guard` accepts an immutable parsed manifest plus a typed observation object and returns `PASS` or one typed failure. It imports no GitHub API, credential, token-mint, workflow-dispatch, ref-update or Workstream-D live execution provider.

A complete observation is shape-validated before semantic comparison. It binds an explicit timezone-aware UTC `evaluated_at` instant plus the exact operation, control repository/commit/tree/workflow/module identities, protocol and state identities, operator/workflow baselines, App boundary, environment policy and exact execution-enable variable name/absence. Malformed complete observations are `OBSERVATION_SHAPE_UNSUPPORTED`; unavailable/rate-limited/ambiguous acquisition is kept in the distinct observation-incomplete lane.

When an owner observation is required, the common evaluator owns its freshness decision. Matching observation identity/digest and any caller-supplied validity state cannot override the manifest's `valid_through` boundary: the observation is stale and produces `APP_BOUNDARY_CHANGED` when `evaluated_at >= valid_through`. This keeps the freshness rule inside the same semantic guard used by future preflight/L1/L2 callers rather than delegating the deadline decision to those adapters.

Failure classes follow the reviewed Slice A design.

Authority/security failures:

- `GOVERNANCE_RECORD_INVALID`
- `GOVERNANCE_AMBIGUOUS`
- `GOVERNANCE_SUPERSEDED`
- `AUTHORITY_NOT_GRANTED`
- `AUTHORITY_CONSUMED`
- `WORKSTREAM_E_NOT_AUTHORISED`

Mutable invalidators:

- `CONTROL_IDENTITY_CHANGED`
- `WORKFLOW_IDENTITY_CHANGED`
- `PROTOCOL_IDENTITY_CHANGED`
- `STATE_BASELINE_CHANGED`
- `OPERATOR_HISTORY_CHANGED`
- `WORKFLOW_HISTORY_CHANGED`
- `APP_BOUNDARY_CHANGED`
- `ENVIRONMENT_BOUNDARY_CHANGED`
- `EXECUTION_ENABLEMENT_CHANGED`

Observation-incomplete failures:

- `READ_EVIDENCE_UNAVAILABLE`
- `READ_EVIDENCE_RATE_LIMITED`
- `READ_EVIDENCE_AMBIGUOUS`

Implementation-defect failures:

- `MANIFEST_SCHEMA_UNSUPPORTED`
- `OBSERVATION_SHAPE_UNSUPPORTED`
- `GUARD_EVALUATOR_DEFECT`

Every non-PASS result is diagnostic only. Nothing in B1 authorises automatic refresh, repair, redispatch, authority reuse or mutation.

The preflight stage requires the exact manifest-bound proposal/readiness/authority lineage and all typed observations. Live-stage evaluation additionally requires an exact accepted `manifest_approval` record for that manifest and authority. The future B2/B3 integrations must call this same evaluator rather than implement parallel semantics.

## Activation boundary

B1 is intentionally inert. In particular it does not modify:

- `.github/workflows/phase2-adversarial.yml`;
- `phase2/operator_capsule.py` V1 discovery/consumption semantics;
- `phase2/operator_runtime.py` current preflight/live adapter;
- credential or App token providers;
- `phase2/workstream_d_live.py` or its recovery/revocation helpers;
- the existing public operator-history issue;
- any environment, App installation/repository selection, repository setting or retained state.

B2 remains responsible for the separate non-authorising preflight projection and genuinely key-free workflow path. B3 remains responsible for the successor execution capsule plus live L1/L2 integration and runtime-visible invalidation checks. Each remains separately reviewed and authorised.

No B1 result creates merge, live execution, workflow-dispatch, credential, state-mutation, recovery or Workstream-E authority.
