"""Workstream D adversarial integration contract and evidence machinery.

This module is credential-free by default.  It defines the immutable scenario
catalogue, attempt isolation rules, fault controls, evidence schema and the
fail-closed driver used by both PR validation and the later trusted-main live
execution gate.  It does not mint credentials or mutate GitHub/canonical state.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Protocol, Sequence

PROTOCOL = "beads-allocation/v0.2"
CANONICAL_REF = "refs/dolt/data"
WORKSTREAM = "D"
SCENARIO_IDS = tuple(range(1, 15))
_ALLOWED_DURABILITY = frozenset({"github_issue", "github_repository", "github_ref", "github_actions"})
_ATTEMPT_RE = re.compile(r"^wd-(?P<run>[1-9][0-9]*)-(?P<attempt>[1-9][0-9]*)-(?P<nonce>[a-z0-9]{6,24})$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class AdversarialContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: int
    name: str
    initial_state: str
    event_or_fault: str
    canonical_expectation: str
    projection_expectation: str
    assertions: tuple[str, ...]
    client_contracts: tuple[str, ...] = ()
    fault_controls: tuple[str, ...] = ()
    live_only: bool = False

    def validate(self) -> None:
        if self.scenario_id not in SCENARIO_IDS:
            raise AdversarialContractError("UNAPPROVED_SCENARIO")
        if not all((self.name, self.initial_state, self.event_or_fault,
                    self.canonical_expectation, self.projection_expectation)):
            raise AdversarialContractError("INCOMPLETE_SCENARIO")
        if not self.assertions:
            raise AdversarialContractError("OBSERVATION_ONLY_SCENARIO")
        for assertion in self.assertions:
            text = assertion.strip().lower()
            if not text or text.startswith(("observe ", "print ", "inspect only")):
                raise AdversarialContractError("OBSERVATION_ONLY_ASSERTION")
        allowed_clients = {"git-capable", "github-api-only"}
        if any(client not in allowed_clients for client in self.client_contracts):
            raise AdversarialContractError("UNKNOWN_CLIENT_CONTRACT")


SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        1, "simultaneous allocate-next",
        "two ready tasks; no allocations",
        "two close-timed ALLOCATE_NEXT requests",
        "two terminal requests and two ACTIVE allocations on distinct tasks with matching uniqueness and Beads mirrors",
        "two exact-anchor ALLOCATED projections",
        (
            "exactly two active allocation rows exist",
            "the two allocation rows reference different task IDs and allocation IDs",
            "each active uniqueness row and Beads status/assignee mirror agrees with its allocation row",
            "deterministic task ordering is preserved",
        ),
        fault_controls=("close_timed_requests",),
        live_only=True,
    ),
    ScenarioSpec(
        2, "simultaneous nominated-task exclusion",
        "one ready nominated task; no allocation",
        "two close-timed ALLOCATE_TASK requests for the same task",
        "one ACTIVE allocation and one terminal TASK_ALREADY_ALLOCATED rejection",
        "one ALLOCATED and one rejection projection",
        (
            "exactly one active allocation exists for the nominated task",
            "the successful allocation and Beads mirror agree",
            "the rejected request creates no second ownership row",
        ),
        fault_controls=("close_timed_requests",),
        live_only=True,
    ),
    ScenarioSpec(
        3, "retained-comment durability",
        "at least three ready tasks and retained unedited request comments",
        "three close-timed requests with one queued attempt cancelled",
        "every retained request comment eventually has one terminal canonical request",
        "one terminal projection per canonical request",
        (
            "complete pagination contains every retained source comment ID",
            "no retained source comment is silently skipped after cancellation",
            "reconciliation terminates each retained valid request",
        ),
        fault_controls=("cancel_queued_attempt", "multi_page_comment_fixture"),
        live_only=True,
    ),
    ScenarioSpec(
        4, "idempotent redelivery",
        "one completed request",
        "redeliver the same request ID and semantic payload",
        "no new request, allocation or ownership mutation",
        "the existing result is reproducibly consumable",
        (
            "canonical ref identity is unchanged by the duplicate path",
            "allocation and request row counts do not increase",
        ),
    ),
    ScenarioSpec(
        5, "payload binding",
        "one completed request",
        "reuse the request ID with a changed payload",
        "original canonical result remains unchanged",
        "REQUEST_ID_PAYLOAD_MISMATCH with execution_may_begin false",
        (
            "payload hashes differ",
            "canonical ref identity is unchanged",
            "no ownership row is created or changed",
        ),
    ),
    ScenarioSpec(
        6, "stale-writer compare-and-swap",
        "two writers bootstrapped from the same accepted base",
        "delay one publication until the other succeeds",
        "only the first expected-old-SHA fast-forward is accepted",
        "the losing stale attempt emits no ALLOCATED projection",
        (
            "the second publisher fails with stale-base semantics",
            "the losing mutation is absent from accepted canonical state",
            "no force publication path is available",
        ),
        fault_controls=("delay_publication",),
    ),
    ScenarioSpec(
        7, "push failure before visibility",
        "one ready task",
        "inject canonical publication failure",
        "no new canonical allocation exists",
        "no ALLOCATED projection exists",
        (
            "canonical ref and allocation rows remain unchanged",
            "the result is CANONICAL_PUSH_FAILED or equivalent fail-closed rejection",
        ),
        fault_controls=("fail_canonical_push",),
    ),
    ScenarioSpec(
        8, "projection failure and orphan invalidation",
        "one accepted canonical allocation",
        "fail the first valid projection post and separately inject an orphan projection",
        "ownership remains canonical; orphan records audit-only evidence with no manufactured request",
        "the valid projection is repaired and the orphan is visibly invalidated",
        (
            "repaired projection cites the exact allocation-creation Git and Dolt identities",
            "orphan audit subject contains repository, issue and projection comment ID",
            "orphan handling creates no allocation or request row",
        ),
        fault_controls=("fail_projection_post", "inject_orphan_projection"),
        live_only=True,
    ),
    ScenarioSpec(
        9, "source mutation boundary",
        "uncanonicalised and canonicalised request comments",
        "cancel before mutation and edit/delete both before ingress and after canonicalisation",
        "pre-ingress edit is rejected/withdrawn; retained request is eventually terminal; post-ingress result is immutable",
        "only canonical terminal results are projected and post-ingress mutation is visibly reported",
        (
            "pre-ingress edit cannot recover or claim the original body",
            "unobserved pre-ingress deletion is not claimed durable",
            "post-ingress edit/delete does not change canonical ownership",
            "reconciliation succeeds without the original runner workspace",
        ),
        fault_controls=("edit_before_ingress", "delete_before_ingress", "edit_after_ingress", "delete_after_ingress"),
        live_only=True,
    ),
    ScenarioSpec(
        10, "clean Git-capable reconstruction",
        "accepted allocations and release history",
        "start a fresh client with no .beads and separately inject allocation/Beads mirror mismatch",
        "history reconstructs from durable Git state only when ownership invariant agrees; mismatch fails closed",
        "valid projections correlate; mismatch never grants work",
        (
            "fresh Git-capable client reconstructs request, allocation, owner and release history",
            "mismatch produces CANONICAL_OWNERSHIP_MISMATCH",
            "allocation row remains singular authority",
        ),
        client_contracts=("git-capable",),
        fault_controls=("inject_mirror_mismatch",),
    ),
    ScenarioSpec(
        11, "GitHub-API-only consumption",
        "one accepted allocation and complete projection",
        "consume using only the GitHub issue API",
        "no hidden canonical mutation is required by the client",
        "projection contains every field required to begin and later release",
        (
            "client uses no Git, Beads, Dolt, artifact or workflow-log access",
            "execution begins only when execution_may_begin is true",
            "release instruction and allocation ID are present",
        ),
        client_contracts=("github-api-only",),
        live_only=True,
    ),
    ScenarioSpec(
        12, "authorised release",
        "one ACTIVE allocation with matching Beads mirror",
        "submit an authorised explicit RELEASE request",
        "allocation becomes RELEASED; uniqueness entry is removed; task returns open/unassigned; history remains",
        "RELEASED projection; any later reallocation uses a new allocation ID",
        (
            "release request is canonical and retains reason/evidence",
            "grant event and allocation row are not deleted",
            "ownership invariant changes atomically",
        ),
    ),
    ScenarioSpec(
        13, "authorisation and token scope",
        "authorisation, installation-inventory and token-profile fixtures",
        "exercise static identity negatives, live-installation negatives, inventory drift and token-scope negatives",
        "every rejected path terminates before unapproved canonical access or mutation",
        "AGENT_NOT_AUTHORISED, RELEASE_NOT_AUTHORISED or an explicit fail-closed scope result",
        (
            "static negatives cannot enter the App-key job",
            "wrong-installation/lost-access paths request no state token",
            "exact selected-repository inventory is current and contains only the approved control and state repository IDs",
            "control and state tokens each contain exactly one approved repository and permission profile",
            "cross-repository access is denied",
            "unscoped, default, multi-repository and unapproved-permission token requests are rejected before use",
        ),
        fault_controls=("static_identity_negative", "live_installation_negative", "inventory_drift", "token_scope_negative"),
        live_only=True,
    ),
    ScenarioSpec(
        14, "clean-runner GitHub-only durability",
        "clean runner and isolated attempt namespace",
        "execute the complete Workstream D suite and discard all runner-local state",
        "only approved GitHub issue, repository, ref and Actions records remain durable",
        "all retained result evidence remains retrievable from GitHub",
        (
            "no external durable service is declared or discovered",
            "all fourteen scenario evidence records are complete and executable-assertion based",
            "runner workspace, cache and artifacts are not treated as canonical authority",
        ),
        client_contracts=("git-capable", "github-api-only"),
        live_only=True,
    ),
)


def scenario_catalogue() -> tuple[ScenarioSpec, ...]:
    for scenario in SCENARIOS:
        scenario.validate()
    if tuple(s.scenario_id for s in SCENARIOS) != SCENARIO_IDS:
        raise AdversarialContractError("SCENARIO_COVERAGE_MISMATCH")
    return SCENARIOS


@dataclass(frozen=True)
class AttemptNamespace:
    value: str
    run_id: int
    run_attempt: int

    @classmethod
    def parse(cls, value: str, *, run_id: int, run_attempt: int) -> "AttemptNamespace":
        match = _ATTEMPT_RE.fullmatch(value)
        if match is None:
            raise AdversarialContractError("INVALID_ATTEMPT_NAMESPACE")
        if int(match.group("run")) != run_id or int(match.group("attempt")) != run_attempt:
            raise AdversarialContractError("ATTEMPT_NAMESPACE_MISMATCH")
        return cls(value, run_id, run_attempt)

    def qualify(self, value: str) -> str:
        if not value or any(ch.isspace() for ch in value):
            raise AdversarialContractError("INVALID_ATTEMPT_VALUE")
        return f"{self.value}:{value}"


@dataclass(frozen=True)
class AssertionEvidence:
    name: str
    passed: bool
    expected: str
    actual: str

    def validate(self) -> None:
        if not self.name or not self.expected or not self.actual:
            raise AdversarialContractError("INCOMPLETE_ASSERTION_EVIDENCE")
        if not self.passed:
            raise AdversarialContractError(f"SCENARIO_ASSERTION_FAILED:{self.name}")


@dataclass(frozen=True)
class ScenarioEvidence:
    scenario_id: int
    attempt_namespace: str
    trusted_sha: str
    protocol_sha: str
    workflow_run_id: int
    workflow_run_attempt: int
    source_comment_ids: tuple[int, ...] = ()
    base_ref_shas: tuple[str, ...] = ()
    accepted_ref_shas: tuple[str, ...] = ()
    dolt_commits: tuple[str, ...] = ()
    canonical_rows: tuple[str, ...] = ()
    projection_urls: tuple[str, ...] = ()
    fault_ids: tuple[str, ...] = ()
    assertions: tuple[AssertionEvidence, ...] = ()
    client_transcripts: tuple[str, ...] = ()
    durability_records: tuple[str, ...] = ()
    cleanup_decision: str = "retain"
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        spec = scenario_by_id(self.scenario_id)
        AttemptNamespace.parse(
            self.attempt_namespace,
            run_id=self.workflow_run_id,
            run_attempt=self.workflow_run_attempt,
        )
        if not _FULL_SHA.fullmatch(self.trusted_sha) or not _FULL_SHA.fullmatch(self.protocol_sha):
            raise AdversarialContractError("INVALID_AUTHORITY_SHA")
        if self.workflow_run_id <= 0 or self.workflow_run_attempt != 1:
            raise AdversarialContractError("INVALID_WORKFLOW_ATTEMPT")
        if self.cleanup_decision not in {"retain", "released", "closed"}:
            raise AdversarialContractError("INVALID_CLEANUP_DECISION")
        if len(self.assertions) < len(spec.assertions):
            raise AdversarialContractError("MISSING_EXECUTABLE_ASSERTIONS")
        for assertion in self.assertions:
            assertion.validate()
        if spec.fault_controls and not self.fault_ids:
            raise AdversarialContractError("MISSING_FAULT_IDENTITY")
        if spec.client_contracts and not self.client_transcripts:
            raise AdversarialContractError("MISSING_CLIENT_TRANSCRIPT")
        if self.scenario_id in {1, 2, 3, 8, 9, 11, 12} and not self.source_comment_ids:
            raise AdversarialContractError("MISSING_SOURCE_COMMENT_EVIDENCE")
        if self.scenario_id in {1, 2, 4, 5, 6, 7, 8, 9, 10, 12, 14}:
            if not self.base_ref_shas or not self.accepted_ref_shas or not self.dolt_commits:
                raise AdversarialContractError("MISSING_CANONICAL_IDENTITY_EVIDENCE")
        if self.scenario_id in {1, 2, 4, 5, 7, 8, 9, 10, 12, 14} and not self.canonical_rows:
            raise AdversarialContractError("MISSING_CANONICAL_ROW_EVIDENCE")
        if self.scenario_id in {1, 2, 3, 5, 8, 9, 11, 12, 14} and not self.projection_urls:
            raise AdversarialContractError("MISSING_PROJECTION_EVIDENCE")
        for record in self.durability_records:
            if record not in _ALLOWED_DURABILITY:
                raise AdversarialContractError("EXTERNAL_DURABLE_SERVICE_PRESENT")

    def to_json(self) -> str:
        self.validate()
        return json.dumps(
            {
                "scenario_id": self.scenario_id,
                "attempt_namespace": self.attempt_namespace,
                "trusted_sha": self.trusted_sha,
                "protocol_sha": self.protocol_sha,
                "workflow_run_id": self.workflow_run_id,
                "workflow_run_attempt": self.workflow_run_attempt,
                "source_comment_ids": list(self.source_comment_ids),
                "base_ref_shas": list(self.base_ref_shas),
                "accepted_ref_shas": list(self.accepted_ref_shas),
                "dolt_commits": list(self.dolt_commits),
                "canonical_rows": list(self.canonical_rows),
                "projection_urls": list(self.projection_urls),
                "fault_ids": list(self.fault_ids),
                "assertions": [
                    {
                        "name": a.name,
                        "passed": a.passed,
                        "expected": a.expected,
                        "actual": a.actual,
                    }
                    for a in self.assertions
                ],
                "client_transcripts": list(self.client_transcripts),
                "durability_records": list(self.durability_records),
                "cleanup_decision": self.cleanup_decision,
                "limitations": list(self.limitations),
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def scenario_by_id(scenario_id: int) -> ScenarioSpec:
    if scenario_id not in SCENARIO_IDS:
        raise AdversarialContractError("UNAPPROVED_SCENARIO")
    return SCENARIOS[scenario_id - 1]


class ScenarioBackend(Protocol):
    def execute(self, spec: ScenarioSpec, namespace: AttemptNamespace) -> ScenarioEvidence: ...


@dataclass
class ScenarioDriver:
    backend: ScenarioBackend

    def run(self, scenario_ids: Iterable[int], namespace: AttemptNamespace) -> tuple[ScenarioEvidence, ...]:
        requested = tuple(scenario_ids)
        if not requested:
            raise AdversarialContractError("EMPTY_SCENARIO_SET")
        if len(set(requested)) != len(requested):
            raise AdversarialContractError("DUPLICATE_SCENARIO")
        evidence: list[ScenarioEvidence] = []
        for scenario_id in requested:
            spec = scenario_by_id(scenario_id)
            result = self.backend.execute(spec, namespace)
            if result.scenario_id != scenario_id:
                raise AdversarialContractError("SCENARIO_EVIDENCE_MISMATCH")
            result.validate()
            evidence.append(result)
        return tuple(evidence)


@dataclass
class EvidenceLedger:
    attempt_namespace: AttemptNamespace
    records: dict[int, ScenarioEvidence] = field(default_factory=dict)

    def append(self, evidence: ScenarioEvidence) -> None:
        evidence.validate()
        if evidence.attempt_namespace != self.attempt_namespace.value:
            raise AdversarialContractError("CROSS_ATTEMPT_EVIDENCE")
        if evidence.scenario_id in self.records:
            raise AdversarialContractError("DUPLICATE_SCENARIO_EVIDENCE")
        self.records[evidence.scenario_id] = evidence

    def finalise(self) -> tuple[ScenarioEvidence, ...]:
        missing = [scenario_id for scenario_id in SCENARIO_IDS if scenario_id not in self.records]
        if missing:
            raise AdversarialContractError("INCOMPLETE_WORKSTREAM_D_EVIDENCE")
        ordered = tuple(self.records[scenario_id] for scenario_id in SCENARIO_IDS)
        for evidence in ordered:
            evidence.validate()
        return ordered


def validate_live_gate(
    *,
    repository: str,
    ref: str,
    trusted_sha: str,
    protocol_sha: str,
    expected_trusted_sha: str,
    expected_protocol_sha: str,
    run_attempt: int,
    enabled: bool,
) -> None:
    """Fail closed before any future credential-bearing Workstream D execution."""
    if repository != "8ft0-ai/gitstate-allocation-control":
        raise AdversarialContractError("WRONG_CONTROL_REPOSITORY")
    if ref != "refs/heads/main":
        raise AdversarialContractError("UNTRUSTED_REF")
    if trusted_sha != expected_trusted_sha or not _FULL_SHA.fullmatch(trusted_sha):
        raise AdversarialContractError("TRUSTED_SHA_MISMATCH")
    if protocol_sha != expected_protocol_sha or not _FULL_SHA.fullmatch(protocol_sha):
        raise AdversarialContractError("PROTOCOL_SHA_MISMATCH")
    if run_attempt != 1:
        raise AdversarialContractError("RERUN_NOT_AUTHORISED")
    if not enabled:
        raise AdversarialContractError("WORKSTREAM_D_EXECUTION_DISABLED")


def evidence_summary(records: Sequence[ScenarioEvidence]) -> dict[str, object]:
    ledger_ids = [record.scenario_id for record in records]
    if ledger_ids != list(SCENARIO_IDS):
        raise AdversarialContractError("INCOMPLETE_WORKSTREAM_D_EVIDENCE")
    for record in records:
        record.validate()
    return {
        "protocol": PROTOCOL,
        "workstream": WORKSTREAM,
        "scenarios": len(records),
        "all_assertions_passed": True,
        "external_durable_service_present": False,
        "production_approval": False,
        "workstream_e_authorised": False,
    }
