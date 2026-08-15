# Workstream B canonical state

The authoritative Dolt/MySQL DDL is `schema/001_workstream_b.sql`. It creates
the protocol request, allocation and append-only event tables plus
`active_task_allocations`, whose task primary key provides database-enforced
active-allocation uniqueness without relying on a partial index.

`allocations` is the singular ownership authority. A grant inserts its request,
allocation, active uniqueness entry and Beads assignment in one transaction. A
release retains the allocation and event history while deleting the active
entry and returning the Beads task to open and unassigned in one transaction.
Any disagreement among those representations fails closed as
`CANONICAL_OWNERSHIP_MISMATCH` and records an audit finding.

`phase2.canonical` defines bootstrap identity checks and expected-old-SHA
compare-and-swap publication. The publisher API exposes only a normal
fast-forward push callback; it has no force option. A stale base is discarded,
fresh canonical state is bootstrapped and the request is retried at most three
times. Transport or push failure never installs the candidate state.

Canonical allocation commits initially contain `anchor_status=PENDING` because
a commit cannot contain its own identifier. `record_anchor` subsequently
records the first accepted Git and Dolt identifiers and appends one
`ANCHOR_RECORDED` event without changing task or allocation semantics.

There is intentionally no default live canonical repository implementation in
this workstream. `process_authorised_request` requires an injected repository
and an already-authorised Workstream A context. Repository tests use only the
isolated `LocalCanonicalRepository`; it invokes no GitHub API, Git, Dolt,
workflow or credential path. GitHub projections/reconciliation and every
Workstream C–E operation remain out of scope.
