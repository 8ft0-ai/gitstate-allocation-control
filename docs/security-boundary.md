# Workstream A security boundary

The implementation deliberately separates durable discovery and request authorisation from every App credential.

The static job is supplied from immutable protected-default-branch workflow content. It does not check out repository content. It downloads a fixed allowlist of trusted files at `github.workflow_sha`, verifies the repository and current dedicated control issue metadata, uses only read access to contents and issues, completely paginates the dedicated issue and returns every statically valid protocol candidate in numeric comment-ID order. It does not invent canonical processed state. A later canonical state-aware stage can filter that ordered set and select the oldest unprocessed request without later retained comments being starved by an already-seen source. Event payloads are scan hints and the top-level event installation is never sender evidence.

Static authorisation verifies the exact byte-level transport envelope, schema, bot or human identity, App attribution where applicable and the asserted agent namespace. Static rejection is reported by a separate job with bounded issue-write permission and no App secret. Rejected comments do not prevent later valid comments in the same complete scan from reaching source revalidation.

A separate source-revalidation job checks out only the recorded full workflow SHA with credential persistence disabled. With read-only contents and issues permissions and no App secret, it revalidates the current control-surface metadata and re-fetches every candidate in the ordered set. Edited, deleted or otherwise changed pre-ingress sources are withdrawn or rejected individually without starving later unchanged candidates. Only an unchanged, still-authorised candidate set can make the protected App-key job eligible.

The protected job checks out the same immutable workflow SHA and receives the App key only in its credential-bearing step after the credential-free source job has succeeded. An App JWT then performs the live repository-installation lookup. Any identity, selected-mode or current-access mismatch stops before installation-token minting and before canonical access.

Exactly two reduced, single-repository token profiles exist in code. Each request includes one repository ID and explicit permissions. Returned repository and permission scopes are checked before a token is used. The explicit protected scope probe proves that each token is denied the other repository scope without creating or altering valid repository state. The regular intake path does not mint a state token and performs no canonical read or mutation.

The owner-authenticated complete selected-repository inventory remains a separate governance attestation because the allocator has no standing owner credential. The attestation model rejects added, missing, invalidated and stale inventories. Any installation-setting change invalidates the retained attestation and blocks acceptance until a fresh owner-authenticated audit is retained.

The workflow security contract is checked structurally rather than by substring presence. The dependency-free validator parses the expected job graph, permissions, dependencies, conditions, checkout refs, action pins, environment placement and secret-bearing boundary, and negative tests prove that unsafe mutations are rejected.

The request-side reporting, source-revalidation and credentialed live-check paths are inactive unless the explicit `PHASE2_INTAKE_ENABLED=true` activation variable is introduced through a later reviewed change. Manual `workflow_dispatch` defaults to operator-authorised reconciliation through the same deterministic complete scan. The protected scope probe is a separate explicit manual operation and is the only credentialed operation enabled by this slice.

## Workstream B isolation

The canonical mutation library is downstream of this completed Workstream A
boundary and accepts only an injected, already-authorised request context. It
does not mint an App token, call GitHub, dispatch the intake workflow or post a
result projection. The concrete Git/Dolt adapter has no configured repository,
credential or default live connection: the already-authorised caller must inject
the state-repository URL and a connection factory for the isolated cloned
database explicitly.

The adapter does not check out `refs/dolt/data` as an ordinary Git worktree. It
uses the ref only as an expected-old CAS identity, clones canonical state through
Dolt's Git-remote transport, reads the clone's Dolt `HEAD` before opening the SQL
connection, and then fails closed unless that connection is bound to the same
Dolt head and expected branch. Publication is performed through that bound
connection with normal `DOLT_PUSH('origin', 'main')`, matching pinned Beads'
non-force path. The adapter rechecks the expected old ref before publication,
has no force option and classifies a moved ref as a stale writer requiring a
fresh clone.

The runtime store consumes Beads' maintained `issues.is_blocked` value for
canonical readiness and `capability:*` labels for capability filtering. It does
not implement a competing dependency/gate/wisp readiness algorithm. Fast failure
and concurrency tests use the isolated SQLite conformance fixture and in-memory
CAS repository. Separate credential-free integration tests download only
SHA-256-pinned public Beads v1.1.0 and Dolt v2.1.4 artefacts, use a hash-pinned
PEP-249 client in a throwaway venv, and operate only on temporary local Git-backed
Dolt repositories. They apply the Workstream B DDL and exercise real database
constraints, grant/release atomicity, append-only events, Beads canonical
readiness and non-force stale-writer CAS. No Workstream B test or candidate code
selects the private state repository on its own.
