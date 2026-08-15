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
- one-to-one assertion evidence bound to each exact protocol assertion;
- one explicit, typed fault identity for every required fault control;
- one typed transcript for every required Git-capable/API-only client contract;
- immutable executable/dependency identities and exact scenario exit status;
- scenario-specific source, Git/Dolt, canonical-row, projection and final-owner evidence;
- structured scenario 13 installation-inventory, reduced-token request/returned-scope,
  cross-repository denial and negative token-policy evidence;
- fail-closed evidence validation, including rejection of failed or substituted
  assertions, missing fault/client evidence, cross-attempt evidence and mixed authority;
- scenario 14 GitHub-only durability plus explicit network-destination/dependency inventory;
- cleanup decisions that retain canonical history;
- a final ledger that cannot pass unless all fourteen scenario records validate;
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
- one-to-one assertion, fault and client evidence binding;
- scenario 4 repeated-result projection evidence;
- scenario 6 winner/final-owner evidence;
- scenario 13 exact inventory, token-profile and negative-scope evidence;
- scenario 14 complete GitHub durability and network/dependency inventory;
- immutable executable/dependency identities, successful exit status and Workstream E exclusion.

These PR tests are regression/contract checks. They are not scenario 1–14 live
evidence and must never be cited as such.

## Trusted-main execution gate

`.github/workflows/phase2-adversarial.yml` is manual-only. On an unmerged PR it
can perform only credential-free contract validation. The protected live gate is
fail-closed unless all of the following are true at execution time:

- repository is exactly `8ft0-ai/gitstate-allocation-control`;
- ref is exactly protected `main`;
- workflow run attempt is exactly `1`;
- the supplied expected control and protocol SHAs equal the immutable trusted
  values being authorised for that run;
- `PHASE2_WORKSTREAM_D_EXECUTION_ENABLED=true` is present in repository Actions
  variables;
- a run-bound attempt namespace matches the current run ID and attempt;
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
each scenario 1–14 under the same attempt namespace and authority identities.
Evidence is not accepted if an assertion is missing, duplicated, substituted or
failed; a required fault or client contract lacks its own typed evidence; a
required source/ref/Dolt/row/projection/final-owner field is missing; executable
or dependency identity is absent; the scenario exit status is non-zero; the run
is a rerun; evidence crosses attempts; or a durable service outside GitHub
Issues, repositories, refs or Actions is relied upon.

Scenario 13 additionally requires a current exact two-repository installation
inventory, explicit single-repository reduced control/state token requests,
validated returned repository/permission scopes, cross-repository denial and
all required negative token-policy results. Scenario 14 requires the complete
GitHub durability category inventory and a recorded network-destination inventory.
The final summary derives the external-durability result from validated evidence;
it does not assert that result independently of the records.

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
- implement scenario 15 or Workstream E;
- approve production use.
