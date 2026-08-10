# Workstream A security boundary

The implementation deliberately separates durable discovery and request authorisation from every App credential.

The static job is supplied from immutable protected-default-branch workflow content. It does not check out repository content. It downloads a fixed allowlist of trusted files at `github.workflow_sha`, verifies the repository and current dedicated control issue metadata, uses only read access to contents and issues, completely paginates the dedicated issue, sorts by numeric comment ID and chooses the oldest unprocessed protocol comment. Event payloads are scan hints and the top-level event installation is never sender evidence.

Static authorisation verifies the exact byte-level transport envelope, schema, bot or human identity, App attribution where applicable and the asserted agent namespace. Static rejection is reported by a separate job with bounded issue-write permission and no App secret.

A separate source-revalidation job checks out only the recorded full workflow SHA with credential persistence disabled. With read-only contents and issues permissions and no App secret, it revalidates the current control-surface metadata and re-fetches the selected source comment. Only an unchanged, still-authorised source can make the protected App-key job eligible.

The protected job checks out the same immutable workflow SHA and receives the App key only in its credential-bearing step after the credential-free source job has succeeded. An App JWT then performs the live repository-installation lookup. Any identity, selected-mode or current-access mismatch stops before installation-token minting and before canonical access.

Exactly two reduced, single-repository token profiles exist in code. Each request includes one repository ID and explicit permissions. Returned repository and permission scopes are checked before a token is used. The explicit protected scope probe proves that each token is denied the other repository scope without creating or altering valid repository state. The regular intake path does not mint a state token and performs no canonical read or mutation.

The owner-authenticated complete selected-repository inventory remains a separate governance attestation because the allocator has no standing owner credential. The attestation model rejects added, missing, invalidated and stale inventories. Any installation-setting change invalidates the retained attestation and blocks acceptance until a fresh owner-authenticated audit is retained.

The request-side reporting, source-revalidation and credentialed live-check paths are inactive unless the explicit `PHASE2_INTAKE_ENABLED=true` activation variable is introduced through a later reviewed change. Manual `workflow_dispatch` defaults to operator-authorised reconciliation through the same deterministic scan. The protected scope probe is a separate explicit manual operation and is the only credentialed operation enabled by this slice.
