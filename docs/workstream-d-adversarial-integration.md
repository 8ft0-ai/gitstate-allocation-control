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
- explicit fault identities instead of unlabelled observation;
- Git-capable and GitHub-API-only client transcript requirements;
- scenario-specific evidence requirements for source comments, base/accepted Git
  refs, Dolt commits, canonical rows and projection URLs;
- fail-closed evidence validation, including rejection of failed assertions,
  cross-attempt evidence and non-GitHub durable services;
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
- exact scenario coverage, attempt isolation, executable-evidence requirements,
  GitHub-only durability and Workstream E exclusion.

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
each scenario 1–14 under the same attempt namespace. Evidence is not accepted if
an assertion failed, a required source/ref/Dolt/row/projection/client/fault field
is missing, the run is a rerun, evidence crosses attempts, or a durable service
outside GitHub Issues, repositories, refs or Actions is relied upon.

Scenario 14 finalisation additionally requires the complete fourteen-record
ledger and records that the result is a bounded GitHub-only proof, not a
production isolation, availability, security or performance claim.

## Non-goals

This candidate does not:

- execute scenarios 1–14;
- use or expose allocator/App credentials;
- bootstrap or mutate live canonical state;
- alter the accepted intake parser or actor policy;
- alter token profiles or cross-repository scope controls;
- alter deterministic selection, canonical ownership, release or no-force CAS
  semantics;
- alter projection/reconciliation ownership rules;
- add leases, expiry, completion orchestration or another protocol capability;
- implement scenario 15 or Workstream E;
- approve production use.
