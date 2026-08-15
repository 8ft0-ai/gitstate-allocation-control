"""Workstream D adversarial integration contract and evidence machinery.

This module is credential-free by default. It defines the immutable scenario
catalogue, attempt isolation rules, fault controls, evidence schema and the
fail-closed driver used by PR validation and the later trusted-main execution
gate. It does not mint credentials or mutate GitHub/canonical state.
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
CONTROL_REPOSITORY_ID = 1321106380
STATE_REPOSITORY_ID = 1317964582
_ALLOWED_DURABILITY = frozenset({"github_issue", "github_repository", "github_ref", "github_actions"})
_APPROVED_TOKEN_PROFILES = {
    "control": (CONTROL_REPOSITORY_ID, frozenset({"metadata:read", "contents:read", "issues:write"})),
    "state": (STATE_REPOSITORY_ID, frozenset({"metadata:read", "contents:write"})),
}
_REQUIRED_TOKEN_NEGATIVES = frozenset({
    "unscoped_token_rejected",
    "default_token_rejected",
    "multi_repository_token_rejected",
    "unapproved_permission_rejected",
    "returned_scope_mismatch_rejected",
    "inventory_drift_blocked",
})
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
        if len(set(self.assertions)) != len(self.assertions):
            raise AdversarialContractError("DUPLICATE_SCENARIO_ASSERTION")
        for assertion in self.assertions:
            text = assertion.strip().lower()
            if not text or text.startswith(("observe ", "print ", "inspect only")):
                raise AdversarialContractError("OBSERVATION_ONLY_ASSERTION")
        allowed_clients = {"git-capable", "github-api-only"}
        if any(client not in allowed_clients for client in self.client_contracts):
            raise AdversarialContractError("UNKNOWN_CLIENT_CONTRACT")
        if len(set(self.client_contracts)) != len(self.client_contracts):
            raise AdversarialContractError("DUPLICATE_CLIENT_CONTRACT")
        if len(set(self.fault_controls)) != len(self.fault_controls):
            raise AdversarialContractError("DUPLICATE_FAULT_CONTROL")


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
class FaultEvidence:
    control: str
    identity: str

    def validate(self) -> None:
        if not self.control or not self.identity:
            raise AdversarialContractError("INCOMPLETE_FAULT_EVIDENCE")


@dataclass(frozen=True)
class ClientTranscript:
    contract: str
    transcript: str

    def validate(self) -> None:
        if self.contract not in {"git-capable", "github-api-only"} or not self.transcript:
            raise AdversarialContractError("INCOMPLETE_CLIENT_TRANSCRIPT")


@dataclass(frozen=True)
class TokenScopeEvidence:
    profile: str
    requested_repository_ids: tuple[int, ...]
    returned_repository_ids: tuple[int, ...]
    requested_permissions: tuple[str, ...]
    returned_permissions: tuple[str, ...]
    restrictions_explicit: bool
    returned_scope_validated: bool
    cross_repository_denied: bool

    def validate(self) -> None:
        if self.profile not in _APPROVED_TOKEN_PROFILES:
            raise AdversarialContractError("UNAPPROVED_TOKEN_PROFILE")
        repository_id, permissions = _APPROVED_TOKEN_PROFILES[self.profile]
        if self.requested_repository_ids != (repository_id,):
            raise AdversarialContractError("TOKEN_REQUEST_REPOSITORY_SCOPE_MISMATCH")
        if self.returned_repository_ids != (repository_id,):
            raise AdversarialContractError("TOKEN_RETURNED_REPOSITORY_SCOPE_MISMATCH")
        if len(set(self.requested_permissions)) != len(self.requested_permissions):
            raise AdversarialContractError("DUPLICATE_REQUESTED_PERMISSION")
        if len(set(self.returned_permissions)) != len(self.returned_permissions):
            raise AdversarialContractError("DUPLICATE_RETURNED_PERMISSION")
        if frozenset(self.requested_permissions) != permissions:
            raise AdversarialContractError("TOKEN_REQUEST_PERMISSION_SCOPE_MISMATCH")
        if frozenset(self.returned_permissions) != permissions:
            raise AdversarialContractError("TOKEN_RETURNED_PERMISSION_SCOPE_MISMATCH")
        if not self.restrictions_explicit:
            raise AdversarialContractError("TOKEN_RESTRICTIONS_NOT_EXPLICIT")
        if not self.returned_scope_validated:
            raise AdversarialContractError("TOKEN_RETURNED_SCOPE_NOT_VALIDATED")
        if not self.cross_repository_denied:
            raise AdversarialContractError("CROSS_REPOSITORY_DENIAL_NOT_PROVEN")


@dataclass(frozen=True)
class ScenarioEvidence:
    scenario_id: int
    attempt_namespace: str
    trusted_sha: str
    protocol_sha: str
    workflow_run_id: int
    workflow_run_attempt: int
    control_repository_id: int
    state_repository_id: int
    exit_status: int
    source_comment_ids: tuple[int, ...] = ()
    base_ref_shas: tuple[str, ...] = ()
    accepted_ref_shas: tuple[str, ...] = ()
    dolt_commits: tuple[str, ...] = ()
    canonical_rows: tuple[str, ...] = ()
    projection_urls: tuple[str, ...] = ()
    fault_ids: tuple[FaultEvidence, ...] = ()
    assertions: tuple[AssertionEvidence, ...] = ()
    client_transcripts: tuple[ClientTranscript, ...] = ()
    executable_blob_shas: tuple[str, ...] = ()
    dependency_identities: tuple[str, ...] = ()
    durability_records: tuple[str, ...] = ()
    final_owner_evidence: tuple[str, ...] = ()
    installation_inventory_repository_ids: tuple[int, ...] = ()
    installation_inventory_current: bool = False
    installation_inventory_attestation: str = ""
    token_scope_records: tuple[TokenScopeEvidence, ...] = ()
    token_policy_negative_results: tuple[str, ...] = ()
    network_destinations: tuple[str, ...] = ()
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
        if self.control_repository_id != CONTROL_REPOSITORY_ID or self.state_repository_id != STATE_REPOSITORY_ID:
            raise AdversarialContractError("REPOSITORY_IDENTITY_MISMATCH")
        if self.exit_status != 0:
            raise AdversarialContractError("SCENARIO_EXIT_STATUS_FAILED")
        if self.cleanup_decision not in {"retain", "released", "closed"}:
            raise AdversarialContractError("INVALID_CLEANUP_DECISION")

        assertion_names = tuple(assertion.name for assertion in self.assertions)
        if assertion_names != spec.assertions:
            raise AdversarialContractError("ASSERTION_BINDING_MISMATCH")
        for assertion in self.assertions:
            assertion.validate()

        fault_controls = tuple(fault.control for fault in self.fault_ids)
        if fault_controls != spec.fault_controls:
            raise AdversarialContractError("FAULT_EVIDENCE_BINDING_MISMATCH")
        for fault in self.fault_ids:
            fault.validate()
        if len({fault.identity for fault in self.fault_ids}) != len(self.fault_ids):
            raise AdversarialContractError("DUPLICATE_FAULT_IDENTITY")

        client_contracts = tuple(transcript.contract for transcript in self.client_transcripts)
        if client_contracts != spec.client_contracts:
            raise AdversarialContractError("CLIENT_TRANSCRIPT_BINDING_MISMATCH")
        for transcript in self.client_transcripts:
            transcript.validate()

        if not self.executable_blob_shas or any(not _FULL_SHA.fullmatch(sha) for sha in self.executable_blob_shas):
            raise AdversarialContractError("MISSING_EXECUTABLE_IDENTITY")
        if not self.dependency_identities or any(not identity for identity in self.dependency_identities):
            raise AdversarialContractError("MISSING_DEPENDENCY_IDENTITY")
        if not self.durability_records:
            raise AdversarialContractError("MISSING_DURABILITY_EVIDENCE")
        if len(set(self.durability_records)) != len(self.durability_records):
            raise AdversarialContractError("DUPLICATE_DURABILITY_RECORD")
        for record in self.durability_records:
            if record not in _ALLOWED_DURABILITY:
                raise AdversarialContractError("EXTERNAL_DURABLE_SERVICE_PRESENT")

        if self.scenario_id in {1, 2, 3, 8, 9, 11, 12, 13} and not self.source_comment_ids:
            raise AdversarialContractError("MISSING_SOURCE_COMMENT_EVIDENCE")
        if self.scenario_id in {1, 2, 4, 5, 6, 7, 8, 9, 10, 12, 14}:
            if not self.base_ref_shas or not self.accepted_ref_shas or not self.dolt_commits:
                raise AdversarialContractError("MISSING_CANONICAL_IDENTITY_EVIDENCE")
        if self.scenario_id in {1, 2, 4, 5, 6, 7, 8, 9, 10, 12, 14} and not self.canonical_rows:
            raise AdversarialContractError("MISSING_CANONICAL_ROW_EVIDENCE")
        if self.scenario_id in {1, 2, 3, 4, 5, 8, 9, 11, 12, 14} and not self.projection_urls:
            raise AdversarialContractError("MISSING_PROJECTION_EVIDENCE")
        if self.scenario_id == 6 and not self.final_owner_evidence:
            raise AdversarialContractError("MISSING_FINAL_OWNER_EVIDENCE")

        if self.scenario_id == 13:
            if tuple(sorted(self.installation_inventory_repository_ids)) != tuple(sorted((CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID))):
                raise AdversarialContractError("INSTALLATION_INVENTORY_MISMATCH")
            if not self.installation_inventory_current or not self.installation_inventory_attestation:
                raise AdversarialContractError("STALE_OR_MISSING_INSTALLATION_INVENTORY")
            profiles = tuple(record.profile for record in self.token_scope_records)
            if profiles != ("control", "state"):
                raise AdversarialContractError("TOKEN_SCOPE_EVIDENCE_BINDING_MISMATCH")
            for record in self.token_scope_records:
                record.validate()
            negatives = frozenset(self.token_policy_negative_results)
            if negatives != _REQUIRED_TOKEN_NEGATIVES or len(self.token_policy_negative_results) != len(_REQUIRED_TOKEN_NEGATIVES):
                raise AdversarialContractError("TOKEN_NEGATIVE_EVIDENCE_INCOMPLETE")

        if self.scenario_id == 14:
            if frozenset(self.durability_records) != _ALLOWED_DURABILITY or len(self.durability_records) != len(_ALLOWED_DURABILITY):
                raise AdversarialContractError("GITHUB_DURABILITY_INVENTORY_INCOMPLETE")
            if not self.network_destinations or any(not destination for destination in self.network_destinations):
                raise AdversarialContractError("MISSING_NETWORK_DESTINATION_INVENTORY")

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
                "control_repository_id": self.control_repository_id,
                "state_repository_id": self.state_repository_id,
                "exit_status": self.exit_status,
                "source_comment_ids": list(self.source_comment_ids),
                "base_ref_shas": list(self.base_ref_shas),
                "accepted_ref_shas": list(self.accepted_ref_shas),
                "dolt_commits": list(self.dolt_commits),
                "canonical_rows": list(self.canonical_rows),
                "projection_urls": list(self.projection_urls),
                "fault_ids": [
                    {"control": fault.control, "identity": fault.identity}
                    for fault in self.fault_ids
                ],
                "assertions": [
                    {
                        "name": assertion.name,
                        "passed": assertion.passed,
                        "expected": assertion.expected,
                        "actual": assertion.actual,
                    }
                    for assertion in self.assertions
                ],
                "client_transcripts": [
                    {"contract": transcript.contract, "transcript": transcript.transcript}
                    for transcript in self.client_transcripts
                ],
                "executable_blob_shas": list(self.executable_blob_shas),
                "dependency_identities": list(self.dependency_identities),
                "durability_records": list(self.durability_records),
                "final_owner_evidence": list(self.final_owner_evidence),
                "installation_inventory_repository_ids": list(self.installation_inventory_repository_ids),
                "installation_inventory_current": self.installation_inventory_current,
                "installation_inventory_attestation": self.installation_inventory_attestation,
                "token_scope_records": [
                    {
                        "profile": record.profile,
                        "requested_repository_ids": list(record.requested_repository_ids),
                        "returned_repository_ids": list(record.returned_repository_ids),
                        "requested_permissions": list(record.requested_permissions),
                        "returned_permissions": list(record.returned_permissions),
                        "restrictions_explicit": record.restrictions_explicit,
                        "returned_scope_validated": record.returned_scope_validated,
                        "cross_repository_denied": record.cross_repository_denied,
                    }
                    for record in self.token_scope_records
                ],
                "token_policy_negative_results": list(self.token_policy_negative_results),
                "network_destinations": list(self.network_destinations),
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
            if (
                result.attempt_namespace != namespace.value
                or result.workflow_run_id != namespace.run_id
                or result.workflow_run_attempt != namespace.run_attempt
            ):
                raise AdversarialContractError("CROSS_ATTEMPT_EVIDENCE")
            result.validate()
            evidence.append(result)
        return tuple(evidence)


@dataclass
class EvidenceLedger:
    attempt_namespace: AttemptNamespace
    records: dict[int, ScenarioEvidence] = field(default_factory=dict)

    def append(self, evidence: ScenarioEvidence) -> None:
        evidence.validate()
        if (
            evidence.attempt_namespace != self.attempt_namespace.value
            or evidence.workflow_run_id != self.attempt_namespace.run_id
            or evidence.workflow_run_attempt != self.attempt_namespace.run_attempt
        ):
            raise AdversarialContractError("CROSS_ATTEMPT_EVIDENCE")
        if evidence.scenario_id in self.records:
            raise AdversarialContractError("DUPLICATE_SCENARIO_EVIDENCE")
        if self.records:
            first = next(iter(self.records.values()))
            if (
                evidence.trusted_sha != first.trusted_sha
                or evidence.protocol_sha != first.protocol_sha
                or evidence.control_repository_id != first.control_repository_id
                or evidence.state_repository_id != first.state_repository_id
            ):
                raise AdversarialContractError("MIXED_AUTHORITY_EVIDENCE")
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
    durability = {
        durable_record
        for record in records
        for durable_record in record.durability_records
    }
    external_durable_service_present = any(
        record not in _ALLOWED_DURABILITY for record in durability
    )
    return {
        "protocol": PROTOCOL,
        "workstream": WORKSTREAM,
        "scenarios": len(records),
        "all_assertions_passed": True,
        "external_durable_service_present": external_durable_service_present,
        "production_approval": False,
        "workstream_e_authorised": False,
    }
