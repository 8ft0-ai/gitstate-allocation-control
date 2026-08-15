# gitstate-allocation-control

Public control plane for the bounded Gitstate Phase 2 allocation experiment.

## Public disclosure boundary

Only non-sensitive synthetic identifiers and content are permitted in this repository, its issues, workflow inputs, logs and artefacts. Credentials, personal data, proprietary task content, private repository identities and private issue references are prohibited.

## Request surface

Issue #1 is the sole request surface and must remain open with the trusted control-surface label. A request is exactly one UTF-8 line beginning with `/beads-v0.2 ` followed immediately by one strict JSON object. Requests elsewhere are rejected before App credentials are available.

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

Fast tests retain an in-memory canonical repository; focused adapter tests
additionally exercise the real Beads `issues`/`dependencies`/`labels` contract
and Dolt Git-remote non-force publication semantics. The implementation does not
post GitHub projections, authorise work to begin, mint credentials, dispatch
intake or itself select/access live `refs/dolt/data`. Result projection and
reconciliation remain separate governed work.

Normal request-side writes and credentialed live checks remain fail-closed unless the separately reviewed activation variable `PHASE2_INTAKE_ENABLED` is exactly `true`. Neither Workstream A nor B creates that variable. Manual `workflow_dispatch` defaults to operator reconciliation; the protected scope probe is a separate explicit manual operation and never mutates canonical state.
