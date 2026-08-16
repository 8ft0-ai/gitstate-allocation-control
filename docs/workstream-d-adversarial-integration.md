# Workstream D — adversarial integration harness

This candidate is governed by `8ft0-ai/gitstate-lab#15` and protocol authority
`gitstate-lab@4ad2cebf6c37d21f44e5652a70f5fb4e77da74ae`. The current bounded
post-merge remediation starts from protected control `main`
`ac56941ff1d952a41143e1450fd24275a888f9f8`, follows the approved fixture-only
trusted-main executor design recorded on #15 comment `5306961511`, and addresses
the later fresh-review blockers recorded in control PR #6 comment `5307309792`.

## Purpose

Workstream D is the evidence gate for protocol scenarios 1–14. The existing
harness defines the immutable scenario and evidence contract. The remediation
adds only the missing protected-main execution path needed to exercise that
contract against the dedicated Phase 2 fixture boundary. It does not change the
accepted Workstream B ownership/transaction semantics, Workstream C
projection/reconciliation semantics, runtime sender policy, token profiles, or
any Workstream E capability.

The harness continues to define:

- the exact scenario 1–14 catalogue and executable assertions;
- unique run/attempt-bound namespaces (`wd-<run>-<attempt>-<nonce>`);
- exact expected control/protocol SHAs supplied to the scenario driver, evidence
  ledger and final summary rather than inferred from evidence;
- one-to-one assertion evidence bound to every protocol assertion;
- explicit typed fault identities and contract-owned outcomes;
- clean Git-capable and GitHub-API-only client transcript identities;
- executable path/blob/trusted-commit binding through immutable Git objects;
- the reviewed pinned checkout, Beads, Dolt and PyMySQL dependency identities;
- structured source, Git/Dolt, canonical-row, projection and fault evidence;
- exact retained terminal-request bindings for scenarios 1–3;
- exact repeated-result/non-mutation evidence for scenario 4;
- exact stale-writer/final-owner evidence for scenario 6;
- complete scenario 13 attribution, installation, inventory and token-scope
  negative identities;
- GitHub-only durability plus explicit network-destination inventory for
  scenario 14;
- history-preserving cleanup decisions; and
- a final boundary that never implies production approval or Workstream E
  authority.

## Post-merge fresh-review remediation

The later independent review after PR #6 identified four remaining evidence-path
gaps. This candidate remediates those gaps without expanding the approved
architecture:

1. Scenario 1 still launches the two allocator calls concurrently, but now also
   records the order of successful canonical publications and proves that the
   two allocation-creation publications follow the production ordering rule
   `(priority, creation time, binary task ID)`, rather than merely proving that
   the final selected set contains two distinct tasks.
2. Scenario 3 still cancels an actually queued worker before execution, but the
   retained third protocol-shaped request is now recovered only after the
   accepted full-pagination `ReconciliationService` rediscovers it as an
   unprocessed source and invokes the bounded fixture handler. Direct recovery
   from a pre-known source ID is no longer accepted as the durability witness.
3. Scenario 9 now proves the edited protocol payload is parseable and positively
   authorisable under the unchanged owner/operator policy, applies the real
   pre-ingress discovery edit boundary to the actual edited GitHub source, and
   runs accepted reconciliation after post-ingress edit/delete. The pass requires
   retained `SOURCE_COMMENT_EDITED` / `SOURCE_COMMENT_DELETED` audit findings as
   well as byte-identical canonical ownership rows.
4. Scenario 10 no longer labels a reconstruction performed through the
   credentialled state writer as a clean client. The trusted fixture broker
   captures and SHA-verifies one exact GitHub state-repository mirror using the
   already-approved state token, then exposes that transient mirror read-only.
   The fresh Git-capable client receives no state token, `GIT_ASKPASS`, GitHub
   token or PAT, has terminal prompting disabled, and is guarded from remote
   write commands. The injected Beads/allocation mirror mismatch is now published
   durably and the accepted reconciler must retain
   `CANONICAL_OWNERSHIP_MISMATCH` audit evidence without automatic repair.

Protocol-shaped fixture source comments use the real parser to derive their
payload hash before direct fixture injection into Workstream B. This lets the
accepted reconciler compare retained source payloads to canonical request rows
without creating a new positive runtime sender. The comments remain authored by
the synthetic fixture transport and `policy/actors.json` remains unchanged.

## Candidate validation

Pull-request validation remains credential-free. `contract-check` checks out the
candidate with `persist-credentials: false` and runs both the existing
`tests/test_workstream_d.py` contract suite and
`tests/test_workstream_d_live.py` remediation regressions. Repository CI also
runs dependency-free unittest discovery and Python compilation before the
existing isolated Workstream B real-runtime gate.

The remediation regressions prove, without reading any allocator secret or
performing live mutation, that:

- the live path accepts only `8ft0-ai/gitstate-allocation-control`, protected
  `main`, exact trusted/protocol SHAs, run attempt `1`, the exact attempt
  namespace, explicit fixture mode and explicit execution enablement;
- a failed gate cannot read the App private key;
- the owner-authenticated installation inventory attestation must be current,
  selected-repository mode, and exactly the control/state repository IDs;
- the control/state installation-token profiles remain the existing exact
  single-repository profiles;
- both temporary installation tokens have an explicit revocation path and are
  cleared from the process object after cleanup;
- any pre-existing remote ref fails the one-time fixture bootstrap closed;
- scenario 15 is unreachable and the executor dispatch set is exactly 1–14;
- the module is not imported by normal Phase 2 intake and `policy/actors.json`
  retains no new GitHub App principal;
- scenario 1 binds the deterministic-order witness to successful canonical
  publication order;
- scenario 3 binds cancellation recovery to the accepted reconciler;
- scenario 9 binds pre-ingress parsing/positive-authorisation evidence and
  post-ingress retained source-mutation audit evidence;
- scenario 10 uses a credential-free, write-guarded fresh Git-capable client and
  durable mismatch/reconciliation audit path;
- the workflow remains manual-only, PR validation receives no allocator secret,
  and the live job remains behind the existing protected environment; and
- the result contract explicitly keeps production approval and Workstream E
  false.

The existing Workstream D tests continue to validate the evidence schema,
scenario-specific bindings, exact dependency identities, fault identity and
outcome ownership, token-scope evidence, GitHub durability inventory and
trusted Git-object identity checks. These PR tests remain regression/contract
checks; they are not scenario 1–14 live evidence.

## Fixture-only trusted-main execution path

`.github/workflows/phase2-adversarial.yml` remains `workflow_dispatch` only. It
exposes three bounded operations:

- `contract_check` — credential-free contract/regression validation only;
- `live_authority_gate` — the pre-existing protected-main authority check only;
- `live_scenario_suite` — the fixture-only Workstream D executor, which is not
  authorised merely by being present on `main`.

`live_scenario_suite` is fail-closed unless all of the following are true at
execution time:

- repository is exactly `8ft0-ai/gitstate-allocation-control`;
- ref is exactly protected `main`;
- workflow run attempt is exactly `1`;
- the supplied expected control SHA equals the immutable dispatched `main` SHA;
- the supplied protocol SHA equals
  `4ad2cebf6c37d21f44e5652a70f5fb4e77da74ae`;
- a run-bound attempt namespace matches the current run ID and attempt;
- fixture mode is exactly `workstream-d-synthetic-fixture-v1`;
- `PHASE2_WORKSTREAM_D_EXECUTION_ENABLED=true` is present; and
- the protected `phase-2-allocator` environment approval succeeds.

The workflow performs this complete gate before dependency installation and
before the step that references the App private key. The live step repeats the
same validation before reading the key. A branch or PR version of the code
therefore has no path to allocator credentials.

## Exact installation and credential boundary

The executor reuses the accepted credential helpers and does not add an App
permission or token profile. Before credential use it validates a fresh
owner-authenticated inventory attestation whose App/installation identity,
`selected` repository mode, age and repository set must exactly match:

- control: repository ID `1321106380`;
- state: repository ID `1317964582`.

The attestation is non-secret input; the executor retains only its SHA-256
identity in scenario evidence.

After the static gate and inventory check, the credential sequence is fixed:

1. read the protected App private key, immediately remove its environment entry,
   and create the short-lived App JWT;
2. revalidate exact App ID, installation ID, slug, owner account and selected
   repository mode against the control repository;
3. mint only the control token for repository `1321106380` with exactly
   `metadata:read`, `contents:read`, `issues:write`, validate the returned scope,
   and prove state-repository denial;
4. mint only the state token for repository `1317964582` with exactly
   `metadata:read`, `contents:write`, validate the returned scope, and prove it
   cannot write the public control repository; and
5. after execution or failure, attempt revocation of both installation tokens,
   clear both token strings, and fail a nominally successful run if revocation
   itself fails.

No third runtime token profile is introduced for scenario 10. The trusted
fixture broker may use the already-approved state token to copy the exact private
GitHub canonical ref into a transient mirror, but the client being evaluated
never receives that token and cannot write the brokered mirror. The mirror is
not retained evidence or canonical authority.

No token is passed to checkout, written to a Git config, persisted to an
artifact/cache/output, or included in retained evidence. The App JWT and private
key are not evidence and are never printed.

The temporary repository execution-enable variable remains an owner governance
control rather than becoming a new runtime permission. The workflow deliberately
does not request GitHub Actions administration permission or introduce an owner
credential merely to delete that variable. The fresh live-execution procedure
must remove the enablement immediately after the authorised run; the workflow
result remains explicitly `...PENDING_ENABLEMENT_REMOVAL` until that governance
cleanup is reconciled.

## Isolated state bootstrap

The live executor is valid only for the dedicated first-attempt synthetic
fixture boundary. Before bootstrap it performs an authenticated `git ls-remote
--refs` against `8ft0-ai/gitstate-allocation-state`. Any existing ref — including
an existing `refs/dolt/data` or unrelated retained state — stops execution with
`UNEXPECTED_CANONICAL_STATE`. Nothing is overwritten or reused.

For an empty repository only, the executor uses the already reviewed pinned
Beads `v1.1.0`, Dolt `v2.1.4` and PyMySQL `1.1.2` identities to initialise the
synthetic Beads/Dolt state and apply the accepted Workstream B allocation schema.
Subsequent canonical operations use the existing `DoltCanonicalRepository`,
which preserves expected-old-SHA compare-and-swap publication and exposes no
force path.

All seeded tasks, request identities and fixture transport are qualified by the
authorised Workstream D attempt namespace. No user, production, planning or
other repository content is admitted to the fixture dataset.

## GitHub fixture transport and runtime actor policy

The control-token write surface is limited to the dedicated public allocation
issue. Source/projection comments emitted by the executor are non-sensitive,
synthetic, attempt-qualified Workstream D fixture evidence.

Those fixture comments do **not** become a new positive sender class. The
executor does not modify `policy/actors.json`, does not add the allocator App to
`github_apps`, and is not imported by `phase2-intake.yml` or normal runtime
intake. Positive fixture transactions are injected directly into the already
accepted Workstream B service with an attempt-qualified synthetic context.
Scenario 13 separately exercises the accepted authorisation function and the
required negative App/bot/namespace/installation/inventory/token cases. This
keeps runtime actor policy unchanged while still testing the Workstream D
capability boundary.

Where reconciliation must rediscover a synthetic source, the source body is a
valid `/beads-v0.2` protocol request and its canonical request row stores the
hash produced by the real parser. Normal intake still sees the actual synthetic
App author and therefore gains no new positive authority from that transport.

## Scenario execution and fault boundary

`phase2/workstream_d_live.py` implements only scenarios 1–14. It composes the
accepted Workstream B/C services and exact test-only fault wrappers; it does not
add a general command runner, plugin point or production runtime API.

The bounded fixture handlers cover:

- genuinely close-timed allocator calls plus canonical-publication-order proof
  for deterministic selection;
- a genuinely queued/cancelled worker followed by full-pagination accepted
  reconciliation recovery;
- idempotent redelivery and changed-payload rejection;
- expected-old-SHA stale-writer rejection with no force publication;
- injected canonical-push failure before visibility;
- projection missing/repair and orphan invalidation from canonical state;
- pre/post-ingress source edit/delete boundaries with retained reconciliation
  audit findings;
- credential-free fresh Git-capable reconstruction through a transient exact
  read-only mirror and durable ownership-mismatch detection/audit;
- GitHub-API-only projection consumption;
- explicit history-preserving release;
- every scenario 13 fault identity plus exact current inventory/token evidence;
  and
- GitHub-only reconstruction/durability with explicit network inventory.

Fault injection is attempt-local. It wraps accepted components or mutates only
the synthetic fixture canonical state where the scenario explicitly requires a
durable fault witness. It does not change parser, policy, allocation, CAS,
projection/reconciliation or credential-profile semantics. Scenario 10's
published mirror mismatch intentionally remains fail-closed and unrepaired so
that the retained audit is evidence of the actual fault rather than a transient
rollback-only observation.

## Evidence and durability boundary

Every live scenario result is validated by the existing `ScenarioEvidence`,
`ScenarioDriver` and `EvidenceLedger` contract under one exact run/attempt,
trusted control SHA and protocol SHA. The executor adds its own immutable
`phase2/workstream_d_live.py` blob identity to each evidence record while
retaining all previously required executable identities and pinned dependency
identities.

Durable evidence remains limited to GitHub Issues, GitHub repositories/refs and
GitHub Actions. Scenario 14 records transient network destinations used by the
bounded execution path; no external service is introduced as canonical or
retained evidence storage. The scenario-10 local mirror is transient client
transport only and is removed with the temporary workspace.

The public final summary contains only run/attempt authority identities,
scenario-evidence SHA-256 identities, the inventory-attestation SHA-256 identity
and explicit cleanup/governance flags. It never contains an App JWT, private key
or installation token. The detailed governance reconciliation for #15 occurs
only after credential revocation and log review.

## Cleanup and retained history

Scenario history, accepted canonical Git/Dolt history and public synthetic
fixture evidence are retained because Workstream D is a durability/reconstruction
gate. Cleanup therefore never deletes canonical request/allocation/event history
merely to make the test repository look empty.

The runtime cleanup boundary is instead:

- temporary workspaces, read-only mirrors and local Dolt servers are destroyed;
- both installation tokens are explicitly revoked and cleared;
- the App private key is removed from the process environment after reading;
- no credential-bearing URL is emitted in an error or retained result; and
- the owner removes `PHASE2_WORKSTREAM_D_EXECUTION_ENABLED` immediately after the
  authorised live run, with #15 reconciliation recording that cleanup.

A failed cleanup cannot be converted into a Workstream D pass.

## Authority boundary

This remediation candidate and its PR validation do **not** authorise any live
scenario execution. The prior live authority was consumed before the execution
path gap was discovered. The later fresh review of merged PR #6 also explicitly
kept live execution closed. After this candidate is credential-free validated,
it requires a genuinely fresh independent substantive review before merge.
After any approved merge, scenarios 1–14 still require a fresh owner-authorised
execution session that immediately revalidates current `main`, protocol
authority, protected environment, App installation/inventory and exact reduced
token profiles before any credential is read.

A successful synthetic Workstream D result still does not approve production
use. Workstream E / scenario 15 remains outside this module and requires its own
governed gate.

## Non-goals

This candidate does not:

- execute scenarios 1–14 during PR validation or under previous authority;
- grant a PR branch or normal intake path allocator credentials;
- add or broaden an App permission, token profile or repository installation;
- add the planning repository, another child repository or external durable
  service to runtime scope;
- add a standing owner credential or Actions-administration runtime permission;
- change `policy/actors.json`, parser semantics or the positive runtime sender
  set;
- change deterministic selection, canonical ownership, release, no-force CAS,
  projection or reconciliation semantics;
- add leases, expiry, completion orchestration or another protocol capability;
- implement scenario 15 or Workstream E; or
- approve production use.
