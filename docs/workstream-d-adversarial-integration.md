# Workstream D — adversarial integration harness

This candidate is governed by `8ft0-ai/gitstate-lab#15` and protocol authority
`gitstate-lab@4ad2cebf6c37d21f44e5652a70f5fb4e77da74ae`. It starts from trusted
control `main` `162832b59652740a07769b3e04cedbcab27921b5`.

## Purpose

Workstream D is the evidence gate for protocol scenarios 1–14. This candidate
adds the bounded harness contract needed to execute and adjudicate those
scenarios without changing the accepted Workstream B ownership/transaction
semantics or Workstream C projection/reconciliation semantics.

The harness defines:

- the exact scenario 1–14 catalogue and executable assertions;
- unique run/attempt-bound namespaces (`wd-<run>-<attempt>-<nonce>`);
- exact expected control/protocol SHAs supplied to the scenario driver, evidence
  ledger and final summary rather than inferred from the first evidence record;
- one-to-one assertion evidence bound to each exact protocol assertion;
- one explicit typed fault identity and outcome for every required fault control,
  with each identity exactly qualified by the authorised run/attempt namespace and
  each recorded actual outcome required to equal its expected fail-closed outcome;
- one typed clean-environment transcript digest for every required
  Git-capable/API-only client contract;
- executable identities containing path, blob SHA and the exact trusted commit
  SHA, plus the retained exact `git ls-tree <trusted-commit> -- <path>` entry and
  `<trusted-commit>:<path>` object specification; validation independently reruns
  read-only Git object queries against the locally available trusted commit and
  requires both the actual tree entry and resolved blob object to match, so a
  fabricated but self-consistent retained identity cannot pass;
- the complete reviewed pinned dependency set for checkout, Beads, Dolt and
  PyMySQL;
- structured scenario-specific source, Git/Dolt, canonical-row and projection
  evidence;
- exact evidence cardinality for the multi-request scenarios: scenarios 1 and 2
  require two distinct source comments, two accepted canonical publications/two
  Dolt identities, at least two canonical row records and exactly two projections;
  scenario 3 requires at least three distinct retained source comments and at least
  one terminal accepted ref, Dolt identity, canonical-row record and projection per
  retained request;
- scenario 4 repeated-result evidence that requires identical projection
  digests, an unchanged canonical ref and unchanged request/allocation row counts;
- scenario 6 winner/final-owner evidence that requires the final allocation and
  final accepted ref to equal the winning publication and excludes the stale allocation;
- scenario 13 evidence with each required attribution, bot, installation,
  namespace/release, inventory and token-policy negative represented as its own
  exact fault control rather than an umbrella result name;
- scenario 14 GitHub-only durability plus explicit network-destination inventory;
- cleanup decisions that retain canonical history;
- a final ledger that cannot pass unless all fourteen records belong to the same
  authorised run/attempt and exact trusted/protocol SHAs; and
- an explicit result boundary that does not imply production approval or permit
  Workstream E.

## Candidate validation

Pull-request validation is credential-free. `tests/test_workstream_d.py` checks
both the harness itself and representative accepted B/C semantics using only the
isolated `LocalCanonicalRepository` fixture. In particular it verifies:

- deterministic distinct `ALLOCATE_NEXT` allocation;
- one-owner exclusion for simultaneous nominated-task semantics;
- duplicate delivery idempotency;
- changed-payload request-ID rejection without canonical mutation;
- expected-old-SHA stale-writer rejection with no force path;
- push failure before visibility;
- history-preserving explicit release;
- exact scenario coverage and run/attempt isolation;
- exact-authority binding in the driver, ledger and final summary;
- one-to-one assertion, fault and client evidence binding;
- fail-closed rejection of scenario-13 fault evidence whose identity is outside
  the authorised attempt or whose actual outcome differs from its expected outcome;
- exact two-request evidence for scenarios 1 and 2 and three-or-more retained,
  terminal canonical request evidence for scenario 3;
- scenario 4 exact repeated-result/non-mutation evidence;
- scenario 6 exact winner/final-owner/ref evidence;
- scenario 13 individual negative-fixture coverage plus exact inventory and token scopes;
- scenario 14 complete GitHub durability and network inventory;
- executable path/blob/trusted-commit binding by reading the actual checked-out
  Git object database for the trusted commit and rejecting a fabricated
  self-consistent tree entry/blob pair, plus an exact complete pinned dependency
  identity set; and
- successful exit status and Workstream E exclusion.

These PR tests are regression/contract checks. They are not scenario 1–14 live
evidence and must never be cited as such.

## Trusted-main execution gate

`.github/workflows/phase2-adversarial.yml` remains manual-only. On an unmerged
PR it can perform only credential-free contract validation. The protected live
gate is fail-closed unless all of the following are true at execution time:

- repository is exactly `8ft0-ai/gitstate-allocation-control`;
- ref is exactly protected `main`;
- workflow run attempt is exactly `1`;
- the supplied expected control and protocol SHAs equal the immutable trusted
  values being authorised for that run;
- `PHASE2_WORKSTREAM_D_EXECUTION_ENABLED=true` is present in repository Actions
  variables;
- a run-bound attempt namespace matches the current run ID and attempt; and
- protected `phase-2-allocator` environment approval succeeds.

The live operation intentionally stops at the authority/evidence-plan boundary
in this candidate. It does not mint the allocator App credential, bootstrap or
mutate `refs/dolt/data`, post request/projection comments or execute any of the
fourteen scenarios merely because the harness PR exists. Those actions require
a separate owner-authorised post-merge execution session that revalidates the
current App inventory, token profiles, branch/environment controls and exact
trusted SHAs immediately before credential use.

This separation is deliberate: merge of the harness makes the scenario/evidence
contract immutable on protected `main`; it does not itself grant live execution
authority.

## Evidence boundary

A live Workstream D pass requires one validated `ScenarioEvidence` record for
each scenario 1–14 under the same attempt namespace and the exact authority
identities supplied by the owner-authorised run. Neither the scenario driver,
ledger nor final summary accepts a different but syntactically valid control or
protocol SHA. A first record therefore cannot redefine the authority boundary.

Evidence is rejected if an assertion is missing, duplicated, substituted or
failed; a required individual fault lacks its exact run/attempt-qualified identity,
records a failed fixture, or records an actual outcome different from its expected
outcome; a client contract lacks a clean transcript digest; required
source/ref/Dolt/row or projection evidence is absent or under-counted for scenarios
1–3; an executable path/blob is not independently resolved from the exact trusted
commit's Git tree and matched to the retained tree entry/blob identity; the trusted
commit object is unavailable to the verifier; the pinned dependency set differs;
the scenario exits non-zero; the run is a rerun; evidence crosses runs/attempts; or
durability relies on a service outside GitHub Issues, repositories, refs or Actions.

Scenario 4 additionally requires proof that the repeated result envelope is
identical and that neither the canonical ref nor request/allocation row counts
change. Scenario 6 additionally requires a structured winner/final-owner record
whose owner and final ref match the winning accepted publication. Scenario 13
requires a current exact two-repository installation inventory, exact reduced
control/state token request and returned scopes, cross-repository denial, and
individual evidence for every required negative fixture. Scenario 14 requires
the complete GitHub durability category inventory and a recorded network
inventory. The final summary is derived only after the complete exact-authority
ledger revalidates all fourteen records.

## Non-goals

This candidate does not:

- execute scenarios 1–14;
- use or expose allocator/App credentials;
- bootstrap or mutate live canonical state;
- alter the accepted intake parser or actor policy;
- alter token profiles or cross-repository scope controls;
- alter deterministic selection, canonical ownership, release or no-force CAS semantics;
- alter projection/reconciliation ownership rules;
- add leases, expiry, completion orchestration or another protocol capability;
- implement scenario 15 or Workstream E; or
- approve production use.
