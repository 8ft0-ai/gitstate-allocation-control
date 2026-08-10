# gitstate-allocation-control

Public control plane for the bounded Gitstate Phase 2 allocation experiment.

## Public disclosure boundary

Only non-sensitive synthetic identifiers and content are permitted in this repository, its issues, workflow inputs, logs and artefacts. Credentials, personal data, proprietary task content, private repository identities and private issue references are prohibited.

## Request surface

Issue #1 is the sole request surface and must remain open with the trusted control-surface label. A request is exactly one UTF-8 line beginning with `/beads-v0.2 ` followed immediately by one strict JSON object. Requests elsewhere are rejected before App credentials are available.

## Trust boundary

The static job validates the repository and current control-surface metadata, completely discovers comments, strictly parses requests and authorises actor namespaces with a read-only workflow token and no checkout. Before a request can reach the protected App-key step, a separate credential-free job revalidates the current control surface and source comment at the immutable workflow SHA.

The protected job receives the App key only after those request-side gates succeed. It then checks the live selected installation and current control-repository access before any reduced installation token can be requested.

This Workstream A implementation does not allocate, release, mutate canonical state or authorise work to begin.

Normal request-side writes and credentialed live checks remain fail-closed unless the separately reviewed activation variable `PHASE2_INTAKE_ENABLED` is exactly `true`. Workstream A does not create that variable. Manual `workflow_dispatch` defaults to operator reconciliation; the protected scope probe is a separate explicit manual operation and never mutates canonical state.
