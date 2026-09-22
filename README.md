# gitstate-allocation-control

Public control plane for the bounded Gitstate Phase 2 allocation experiment.

## Public disclosure boundary

Only non-sensitive synthetic identifiers and content are permitted in this repository, its issues, workflow inputs, logs and artefacts. Credentials, personal data, proprietary task content, private repository identities and private issue references are prohibited.

## Request surfaces

### Allocation intake

Issue #1 is the sole `/beads-v0.2` allocation-intake request surface and must remain open with the trusted control-surface label. An allocation-intake request is exactly one UTF-8 line beginning with `/beads-v0.2 ` followed immediately by one strict JSON object. Allocation-intake requests elsewhere are rejected before App credentials are available.

### Governed `current_observation` same-run protected execution

A separately governed same-run path may accept one dedicated issue for one `current_observation` attempt. This path is not an allocation-intake surface and grants no allocation, retry, Workstream D or Workstream E authority.

The request issue must be opened by repository owner `8ft0-ai`, have the exact title:

```text
[gitstate-current-observation-dispatch/v1]
```

and contain exactly one UTF-8 line with one strict JSON object containing only:

```json
{"ref":"refs/tags/gitstate-current-observation/<40-lowercase-hex>","current_observation_recipient_cert_b64":"<public-base64-DER-X509-certificate>"}
```

The path is structurally fixed to repository `8ft0-ai/gitstate-allocation-control` and the owner-authenticated `issues: opened` workflow. The static validation job performs only credential-free request checks. The single consequence job then enters the existing `phase-2-allocator` protected environment and, before the first durable write or allocator observation, independently requires request identity, run-attempt identity and immutable subject identity to agree: protected `main` execution, owner actor and triggering actor, run attempt 1, workflow SHA equal to execution SHA, and a direct governed tag target whose 40-hex suffix equals that same SHA.

Only after those gates pass may the protected job lazily use the allocator App key to prove the fixed App registration, live installation identity and the exact reduced `environments:read` + `metadata:read` capability by minting, using and positively revoking the control-repository environment-observation token. That proof and the durable consequence are colocated: only after the live capability proof succeeds does the same protected job write and positively re-read exactly one public-safe consumption marker. It then independently reconstructs the current request, exact marker and governed tag again before entering the existing observation engine. No second `workflow_dispatch`, outbound dispatch transport or `actions: write` authority exists on this path. The public recipient certificate is reconstructed from the freshly revalidated request body and is not echoed to logs, summaries or diagnostics; recipient private-key material is never accepted.


#### Immutable runtime-subject rollover

A consumed `current_observation` subject is not a reusable execution identity. Because protected execution is fixed to `main` and requires the requested direct tag target, `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` to identify the same commit on run attempt 1, a later separately governed observation must use a fresh reviewed protected-`main` commit and a fresh direct `refs/tags/gitstate-current-observation/<commit>` tag.

The immutable observation tag namespace is append-only: an existing subject tag is never moved, replaced or reused for another request. Establishing a fresh runtime subject does not itself create or authorise an observation request, retry, allocation, Workstream D action or Workstream E action; those remain separate governance boundaries.

## Trust boundary

The static job validates the repository and current control-surface metadata, strictly parses requests and authorises actor namespaces with a read-only workflow token. It does not attempt to read allocator App registration metadata, receive allocator credentials or create durable consumption authority.

The protected job receives the App key only inside `phase-2-allocator`. Within that same job, request/run/tag/prior-marker gates precede the first App-key read; App-registration, live-installation and effective environment-read capability are proven immediately before the single consumption write; and request/marker/tag authority is reconstructed again before observation execution.

Workstream A supplies the completed intake and credential boundary. Workstream B
adds the canonical Dolt schema, deterministic allocation/release library and a
no-force expected-old-SHA compare-and-swap implementation. The allocation row is
the singular ownership authority; its active-task uniqueness entry and Beads
status/assignee materialisation change in the same database transaction.

Workstream B includes a concrete Git-backed Dolt repository adapter and Beads
SQL store, but deliberately configures no live state target and accepts no
credential by default. A caller must inject an already-authorised state-repository
URL and connection factory through the Workstream A boundary. The adapter probes
`refs/dolt/data` only as the Git CAS identity, performs a fresh `dolt clone`,
reads the clone's Dolt head before opening the SQL connection, and fails closed
unless that connection is bound to the exact cloned head and expected branch.
It publishes only through that bound connection with normal
`DOLT_PUSH('origin', 'main')` after an expected-old-SHA recheck. It never checks
out or commits the Dolt data ref as an ordinary Git worktree and exposes no
force option.

The concrete store consumes Beads' maintained `issues.is_blocked` readiness
materialisation and `capability:*` labels instead of reimplementing only part of
Beads dependency, gate or wisp semantics. Fast tests retain an in-memory
canonical repository; credential-free integration tests additionally use
cryptographically pinned Beads v1.1.0 and its exact Dolt v2.1.4 dependency
against an isolated local Git-backed Dolt remote. They apply the authoritative
DDL and exercise database constraints, atomic grant/release mirroring,
append-only history, canonical Beads readiness and non-force stale-writer CAS.

The implementation does not post GitHub projections, authorise work to begin,
mint credentials, dispatch intake or itself select/access live `refs/dolt/data`.
Result projection and reconciliation remain separate governed work.

The separately governed Workstream D operator path now includes an additive V2 successor capsule. Its live route requires an exact successful B2 projection, durable carrier-ledger validity, an independently fetched owner-authenticated public-safe manifest-approval attestation and single-use consumption, then runs a capability-denied L1 public-freshness guard before entering the protected environment. The capsule binds approval only by opaque record/digest and attestation ID/digest; raw governance source bodies, source locators and timestamps are not permitted in the public capsule. L2 independently proves current private App inventory and the exact private state baseline with short-lived read-only observation tokens, positively revokes both, and only then permits the existing reduced control/state mutation tokens to be minted. The exact candidate must also be the sole open operator capsule before consumption. This path changes no Workstream B ownership semantics and grants no Workstream E authority.

Normal request-side writes and credentialed live checks remain fail-closed unless the separately reviewed activation variable `PHASE2_INTAKE_ENABLED` is exactly `true`. Neither Workstream A nor B creates that variable. Manual `workflow_dispatch` defaults to operator reconciliation; the protected scope probe is a separate explicit manual operation and never mutates canonical state.
