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

The path is structurally fixed to repository `8ft0-ai/gitstate-allocation-control` and the owner-authenticated `issues: opened` workflow. Before the first durable write it requires the request identity, run-attempt identity and immutable subject identity to agree: protected `main` execution, owner actor and triggering actor, run attempt 1, workflow SHA equal to execution SHA, and a direct governed tag target whose 40-hex suffix equals that same SHA. It then writes and positively re-reads exactly one public-safe consumption marker before entering the existing `phase-2-allocator` environment in the same workflow run.

The protected job independently reconstructs the current request, exact consumption marker and governed tag before allocator private-key use. No second `workflow_dispatch`, outbound dispatch transport or `actions: write` authority exists on this path. The public recipient certificate is reconstructed from the freshly revalidated request body and is not echoed to logs, summaries or diagnostics; recipient private-key material is never accepted.

## Trust boundary

The static job validates the repository and current control-surface metadata, completely discovers comments, strictly parses requests and authorises actor namespaces with a read-only workflow token and no checkout. Before a request can reach the protected App-key step, a separate credential-free job revalidates the current control surface and source comment at the immutable workflow SHA.

The protected job receives the App key only after those request-side gates succeed. It then checks the live selected installation and current control-repository access before any reduced installation token can be requested.

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
