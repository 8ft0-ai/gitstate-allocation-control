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
isolated Git/Dolt adapter: it fetches only `refs/dolt/data` into a fresh detached
workspace, verifies both the Git ref SHA and Dolt `HEAD`, opens a caller-supplied
PEP-249 connection to that isolated database, versions the accepted SQL
transaction in Dolt, wraps the changed database in a child Git commit, rechecks
the expected old ref immediately before publication and performs a normal
non-force push. A stale writer is discarded and retried from fresh state; a
transport failure does not install the candidate state. The adapter exposes no
force option.

The repository URL, state credential and database connection are deliberately
not configured by Workstream B. `process_authorised_request` receives an
injected repository and an already-authorised Workstream A context; the engine
selects the repository-specific Dolt store only through that boundary. The
existing `LocalCanonicalRepository` remains an isolated SQLite fixture for fast
credential-free failure and concurrency tests.

Canonical allocation commits initially contain `anchor_status=PENDING` because
a commit cannot contain its own identifier. `record_anchor` subsequently
records the first accepted Git and Dolt identifiers and appends one
`ANCHOR_RECORDED` event without changing task or allocation semantics.

No GitHub result projection or reconciliation behaviour is implemented here.
No default live state target, allocator token, workflow dispatch or Workstream
C–E operation is introduced by this workstream.
