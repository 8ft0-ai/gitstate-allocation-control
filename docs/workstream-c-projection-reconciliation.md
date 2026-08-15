# Workstream C — canonical projection and reconciliation

This implementation is the credential-free Workstream C candidate governed by
`8ft0-ai/gitstate-lab#14` and authoritative protocol
`gitstate-lab@4ad2cebf6c37d21f44e5652a70f5fb4e77da74ae`.

It does **not** activate live canonical state, mint an allocator credential,
post a real allocation/projection, dispatch the protected workflow or implement
Workstreams D–E.

## Authority boundary

`allocations` remains the singular ownership authority. GitHub issue comments
are durable request/projection visibility only. An `ALLOCATED` projection can be
rendered only when:

- the canonical request is terminal and has a recorded allocation-creation Git
  SHA and Dolt commit;
- its allocation is still active;
- the active-allocation uniqueness row agrees with the allocation row; and
- the Beads status/assignee mirror agrees with that allocation.

Any disagreement fails closed as `CANONICAL_OWNERSHIP_MISMATCH`. Reconciliation
records an audit finding and may invalidate visibility, but it never repairs or
infers ownership from a comment, artifact, cache, runner workspace or Beads
assignee/status alone.

## Projection contract

`phase2.projection` emits exactly one bare JSON object. Every terminal result
contains protocol, request/result identity, source repository/issue/comment,
`refs/dolt/data`, the exact allocation-creation Git SHA, the exact Dolt commit
and `execution_may_begin`.

Only a valid canonical `ALLOCATED` result can set
`execution_may_begin=true`. Allocated results also contain allocation/task
identity, task summary, grant timestamp and the protocol release instruction.

## Reconciliation

`phase2.reconciliation.ReconciliationService` consumes a fully paginated issue
view through an injected gateway and uses the same `CanonicalRepository`
expected-old-SHA publication boundary as Workstream B for metadata changes. It:

- retries a pending canonical anchor only when an injected durable-history
  lookup supplies the exact allocation-creation Git/Dolt identity;
- posts or repairs missing canonical projections;
- canonically marks a failed projection as `MISSING/REQUIRED`;
- records projection URLs/IDs in append-only projection events after a post;
- invalidates projection-shaped comments that cannot be matched to canonical
  state and records a null-request `PROJECTION_COMMENT` audit subject;
- detects post-ingress source edits/deletion without changing terminal results;
- handles same-payload duplicate delivery and payload-mismatch delivery without
  creating a second canonical request or allocation;
- hands genuinely unprocessed request comments back to the trusted-intake
  boundary rather than inventing canonical state;
- reports stale active allocations without leases or automatic expiry; and
- emits a deterministic durable reconciliation summary.

A fresh reconciler instance can recover a successful canonical push followed by
projection failure using only the canonical repository and current control-issue
comments; no prior runner state is required.

## GitHub adapter

`phase2.projection_github.GitHubIssueGateway` is a bounded control-issue adapter.
It performs explicit `per_page=100` pagination until the final short page and
supports only issue-comment reads/writes. It has no state-repository API.
Credential provisioning and use remain outside this implementation gate.

## Operator recovery

`OperatorRecovery` exposes only explicit operator `RELEASE`. It requires an
operator-authorised context and non-empty reason/evidence, then delegates the
mutation to the existing Workstream B allocation service so release uses the
same transaction, ownership invariant and no-force canonical CAS path. There
is no automatic expiry or inferred abandonment.

## Candidate validation

`tests/test_workstream_c.py` uses only `LocalCanonicalRepository`, synthetic
request/task records and mocked GitHub APIs. It covers:

- complete exact-anchor API-only projection consumption;
- projection failure followed by fresh-session repair;
- orphan invalidation without manufacturing request/allocation state;
- fail-closed allocation/Beads disagreement;
- edited-source audit with immutable ownership;
- duplicate and payload-mismatch delivery without ownership advance;
- stale-allocation reporting without expiry;
- unprocessed-request handoff;
- authorised versus unauthorised operator release with retained reason; and
- complete GitHub issue-comment pagination.

The existing CI workflow remains credential-free for pull requests. The
protected `phase2-intake.yml` workflow is intentionally unchanged by this
candidate; live integration/execution remains a separate post-merge governance
gate.
