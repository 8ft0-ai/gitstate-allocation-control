# Workstream B canonical state

The authoritative Dolt/MySQL DDL is `schema/001_workstream_b.sql`. It is applied
inside the same Dolt database as the Beads graph and binds
`allocations.task_id` directly to Beads `issues(id)`. It creates the protocol
request, allocation and append-only event tables plus
`active_task_allocations`, whose task primary key provides database-enforced
active-allocation uniqueness without relying on a partial index.

`allocations` is the singular ownership authority. `phase2.dolt_store` targets
the Beads `issues`, `dependencies` and `labels` tables rather than the isolated
SQLite fixture. A grant inserts its request, allocation and active uniqueness
entry and changes the Beads issue from `open` to `in_progress` with the canonical
agent as assignee through the same SQL transaction. A release retains the
allocation and event history while deleting the active entry and returning the
Beads issue to `open` and unassigned in that same transaction. Any disagreement
among those representations fails closed as `CANONICAL_OWNERSHIP_MISMATCH` and
records an audit finding.

`phase2.canonical` retains the dependency-free identity/CAS abstractions used by
unit tests. `phase2.dolt_repository.DoltCanonicalRepository` is the concrete
isolated Git-backed Dolt adapter. `refs/dolt/data` is treated only as the
expected-old Git CAS identity: the adapter probes it with `git ls-remote`,
normalises the repository URL using the pinned Beads v1.1.0 Git-to-Dolt rules,
and performs a fresh `dolt clone` into an isolated temporary database. Before
opening the caller-supplied PEP-249 connection, it reads the cloned Dolt
`HEAD` through the CLI. Bootstrap then fails closed unless the opened
connection reports that exact `DOLT_HASHOF('HEAD')` and the expected `main`
branch. Ref movement while the clone is in flight invalidates the snapshot.

Publication versions the accepted SQL transaction with `DOLT_ADD` and
`DOLT_COMMIT` through that already-bound connection, rechecks the expected old
`refs/dolt/data` SHA immediately before publication, and then calls normal
`DOLT_PUSH('origin', 'main')` through the same connection. This is the pinned
Beads non-force publication path: no `--force` argument exists, and canonical
data is never published by checking out or committing `refs/dolt/data` as an
ordinary Git worktree. A failed push is classified as stale if the remote CAS
identity moved and otherwise as a canonical push failure; a successful push
must advance the canonical Git ref before an accepted identity is returned.
Bounded stale retries always start from a fresh Dolt clone.

The repository URL, state credential and database connection are deliberately
not configured by Workstream B. `process_authorised_request` receives an
injected repository and an already-authorised Workstream A context; the engine
selects the repository-specific Dolt store only through that boundary. The
existing `LocalCanonicalRepository` remains an isolated SQLite fixture for fast
credential-free failure and concurrency tests.

Canonical allocation commits initially contain `anchor_status=PENDING` because
a commit cannot contain its own identifier. `record_anchor` subsequently records
the first accepted Git and Dolt identifiers and appends one `ANCHOR_RECORDED`
event without changing task or allocation semantics.

No GitHub result projection or reconciliation behaviour is implemented here.
No default live state target, allocator token, workflow dispatch or Workstream
C–E operation is introduced by this workstream.
