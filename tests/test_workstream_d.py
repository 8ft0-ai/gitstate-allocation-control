import hashlib
import unittest

from phase2.adversarial import (
    AdversarialContractError,
    AssertionEvidence,
    AttemptNamespace,
    EvidenceLedger,
    SCENARIO_IDS,
    ScenarioDriver,
    ScenarioEvidence,
    evidence_summary,
    scenario_by_id,
    scenario_catalogue,
    validate_live_gate,
)
from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.canonical import LocalCanonicalRepository, StaleCanonicalBase


TRUSTED_SHA = "a" * 40
PROTOCOL_SHA = "b" * 40
RUN_ID = 31880000000
RUN_ATTEMPT = 1
NAMESPACE = f"wd-{RUN_ID}-{RUN_ATTEMPT}-abc123"
AGENT = "agent://human/8ft0-ai/session/workstream-d"


def task(task_id: str, priority: int = 1) -> Task:
    return Task(
        task_id=task_id,
        task_type="task",
        status="open",
        assignee=None,
        priority=priority,
        created_at="2026-08-15T00:00:00Z",
        ready=True,
        blocked=False,
    )


def command(
    name: str,
    request_type: str,
    *,
    task_id: str | None = None,
    allocation_id: str | None = None,
    reason: str | None = None,
) -> AllocationCommand:
    return AllocationCommand(
        request_id=stable_ulid(f"wd:{name}"),
        request_type=request_type,
        payload_hash=hashlib.sha256(f"wd:{name}".encode()).hexdigest(),
        agent_id=AGENT,
        task_id=task_id,
        allocation_id=allocation_id,
        reason=reason,
        task_types=("task",) if request_type == "ALLOCATE_NEXT" else (),
    )


def context(comment_id: int, *, operator: bool = False) -> RequestContext:
    return RequestContext(
        "8ft0-ai/gitstate-allocation-control",
        1,
        comment_id,
        "user:8ft0-ai",
        AGENT,
        is_operator=operator,
    )


def row_count(repository: LocalCanonicalRepository, table: str) -> int:
    connection = repository.inspect()
    try:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    finally:
        connection.close()


def evidence_for(scenario_id: int, *, passed: bool = True, namespace: str = NAMESPACE) -> ScenarioEvidence:
    spec = scenario_by_id(scenario_id)
    assertions = tuple(
        AssertionEvidence(assertion, passed, "protocol expectation", "matched")
        for assertion in spec.assertions
    )
    source_comments = (1000 + scenario_id,) if scenario_id in {1, 2, 3, 8, 9, 11, 12} else ()
    canonical = scenario_id in {1, 2, 4, 5, 6, 7, 8, 9, 10, 12, 14}
    rows = scenario_id in {1, 2, 4, 5, 7, 8, 9, 10, 12, 14}
    projections = scenario_id in {1, 2, 3, 5, 8, 9, 11, 12, 14}
    return ScenarioEvidence(
        scenario_id=scenario_id,
        attempt_namespace=namespace,
        trusted_sha=TRUSTED_SHA,
        protocol_sha=PROTOCOL_SHA,
        workflow_run_id=RUN_ID,
        workflow_run_attempt=RUN_ATTEMPT,
        source_comment_ids=source_comments,
        base_ref_shas=("1" * 40,) if canonical else (),
        accepted_ref_shas=("2" * 40,) if canonical else (),
        dolt_commits=("dolt-accepted",) if canonical else (),
        canonical_rows=("row-digest",) if rows else (),
        projection_urls=("https://github.example/projection",) if projections else (),
        fault_ids=(f"fault:{scenario_id}",) if spec.fault_controls else (),
        assertions=assertions,
        client_transcripts=("clean-client-transcript",) if spec.client_contracts else (),
        durability_records=("github_issue", "github_repository", "github_ref", "github_actions"),
        cleanup_decision="retain",
        limitations=("bounded proof only",),
    )


class CatalogueTests(unittest.TestCase):
    def test_catalogue_is_exactly_scenarios_1_through_14(self):
        catalogue = scenario_catalogue()
        self.assertEqual(tuple(spec.scenario_id for spec in catalogue), SCENARIO_IDS)
        self.assertEqual(len(catalogue), 14)
        self.assertTrue(all(spec.assertions for spec in catalogue))

    def test_workstream_e_scenario_is_not_present(self):
        with self.assertRaisesRegex(AdversarialContractError, "UNAPPROVED_SCENARIO"):
            scenario_by_id(15)

    def test_attempt_namespace_is_bound_to_run_and_first_attempt(self):
        parsed = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)
        self.assertEqual(parsed.qualify("task-a"), f"{NAMESPACE}:task-a")
        with self.assertRaisesRegex(AdversarialContractError, "ATTEMPT_NAMESPACE_MISMATCH"):
            AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID + 1, run_attempt=1)

    def test_live_gate_is_manual_trusted_main_first_attempt_and_explicitly_enabled(self):
        validate_live_gate(
            repository="8ft0-ai/gitstate-allocation-control",
            ref="refs/heads/main",
            trusted_sha=TRUSTED_SHA,
            protocol_sha=PROTOCOL_SHA,
            expected_trusted_sha=TRUSTED_SHA,
            expected_protocol_sha=PROTOCOL_SHA,
            run_attempt=1,
            enabled=True,
        )
        for override, code in (
            ({"ref": "refs/heads/feature"}, "UNTRUSTED_REF"),
            ({"run_attempt": 2}, "RERUN_NOT_AUTHORISED"),
            ({"enabled": False}, "WORKSTREAM_D_EXECUTION_DISABLED"),
            ({"trusted_sha": "c" * 40}, "TRUSTED_SHA_MISMATCH"),
        ):
            values = dict(
                repository="8ft0-ai/gitstate-allocation-control",
                ref="refs/heads/main",
                trusted_sha=TRUSTED_SHA,
                protocol_sha=PROTOCOL_SHA,
                expected_trusted_sha=TRUSTED_SHA,
                expected_protocol_sha=PROTOCOL_SHA,
                run_attempt=1,
                enabled=True,
            )
            values.update(override)
            with self.assertRaisesRegex(AdversarialContractError, code):
                validate_live_gate(**values)


class EvidenceTests(unittest.TestCase):
    def test_each_scenario_has_complete_executable_evidence_shape(self):
        for scenario_id in SCENARIO_IDS:
            with self.subTest(scenario=scenario_id):
                evidence_for(scenario_id).validate()

    def test_failed_assertion_fails_closed(self):
        with self.assertRaisesRegex(AdversarialContractError, "SCENARIO_ASSERTION_FAILED"):
            evidence_for(4, passed=False).validate()

    def test_external_durable_service_is_rejected(self):
        evidence = evidence_for(14)
        mutated = ScenarioEvidence(
            **{**evidence.__dict__, "durability_records": evidence.durability_records + ("external_database",)}
        )
        with self.assertRaisesRegex(AdversarialContractError, "EXTERNAL_DURABLE_SERVICE_PRESENT"):
            mutated.validate()

    def test_cross_attempt_evidence_is_rejected(self):
        ledger = EvidenceLedger(AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1))
        other = f"wd-{RUN_ID + 1}-1-def456"
        evidence = evidence_for(1, namespace=other)
        with self.assertRaises(AdversarialContractError):
            ledger.append(evidence)

    def test_final_evidence_requires_all_fourteen_scenarios(self):
        namespace = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)
        ledger = EvidenceLedger(namespace)
        for scenario_id in SCENARIO_IDS[:-1]:
            ledger.append(evidence_for(scenario_id))
        with self.assertRaisesRegex(AdversarialContractError, "INCOMPLETE_WORKSTREAM_D_EVIDENCE"):
            ledger.finalise()
        ledger.append(evidence_for(14))
        records = ledger.finalise()
        summary = evidence_summary(records)
        self.assertTrue(summary["all_assertions_passed"])
        self.assertFalse(summary["external_durable_service_present"])
        self.assertFalse(summary["production_approval"])
        self.assertFalse(summary["workstream_e_authorised"])

    def test_driver_rejects_duplicate_scenario_and_backend_mismatch(self):
        namespace = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)

        class Backend:
            def execute(self, spec, attempt):
                return evidence_for(1)

        driver = ScenarioDriver(Backend())
        with self.assertRaisesRegex(AdversarialContractError, "DUPLICATE_SCENARIO"):
            driver.run((1, 1), namespace)
        with self.assertRaisesRegex(AdversarialContractError, "SCENARIO_EVIDENCE_MISMATCH"):
            driver.run((2,), namespace)


class AcceptedSemanticsRegressionTests(unittest.TestCase):
    """Credential-free checks that Workstream D consumes, rather than changes, B/C semantics."""

    def test_scenario_1_distinct_allocate_next_results_are_deterministic(self):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, [task("task-a", 1), task("task-b", 2)])
        service = AllocationService(repository, clock=lambda: "2026-08-15T00:00:00Z")
        first = service.process(command("s1-a", "ALLOCATE_NEXT"), context(101))
        second = service.process(command("s1-b", "ALLOCATE_NEXT"), context(102))
        self.assertEqual((first.status, second.status), ("ALLOCATED", "ALLOCATED"))
        self.assertEqual((first.task_id, second.task_id), ("task-a", "task-b"))
        self.assertNotEqual(first.allocation_id, second.allocation_id)
        self.assertEqual(row_count(repository, "active_task_allocations"), 2)

    def test_scenario_2_same_task_cannot_have_two_active_owners(self):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, [task("task-only")])
        service = AllocationService(repository, clock=lambda: "2026-08-15T00:00:00Z")
        first = service.process(command("s2-a", "ALLOCATE_TASK", task_id="task-only"), context(201))
        second = service.process(command("s2-b", "ALLOCATE_TASK", task_id="task-only"), context(202))
        self.assertEqual(first.status, "ALLOCATED")
        self.assertEqual((second.status, second.reason_code), ("REJECTED", "TASK_ALREADY_ALLOCATED"))
        self.assertEqual(row_count(repository, "active_task_allocations"), 1)

    def test_scenario_4_duplicate_delivery_does_not_advance_canonical_ref(self):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, [task("task-idempotent")])
        service = AllocationService(repository, clock=lambda: "2026-08-15T00:00:00Z")
        request = command("s4", "ALLOCATE_TASK", task_id="task-idempotent")
        first = service.process(request, context(401))
        accepted = repository.identity
        duplicate = service.process(request, context(401))
        self.assertEqual(duplicate.allocation_id, first.allocation_id)
        self.assertFalse(duplicate.ref_advanced)
        self.assertEqual(repository.identity, accepted)

    def test_scenario_5_payload_mismatch_is_non_mutating(self):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, [task("task-payload")])
        service = AllocationService(repository, clock=lambda: "2026-08-15T00:00:00Z")
        original = command("s5", "ALLOCATE_TASK", task_id="task-payload")
        granted = service.process(original, context(501))
        accepted = repository.identity
        mismatch = AllocationCommand(
            request_id=original.request_id,
            request_type=original.request_type,
            payload_hash="f" * 64,
            agent_id=AGENT,
            task_id="task-payload",
        )
        rejected = service.process(mismatch, context(502))
        self.assertEqual(granted.status, "ALLOCATED")
        self.assertEqual((rejected.status, rejected.reason_code), ("REJECTED", "REQUEST_ID_PAYLOAD_MISMATCH"))
        self.assertEqual(repository.identity, accepted)
        self.assertEqual(row_count(repository, "allocations"), 1)

    def test_scenario_6_stale_writer_is_rejected_without_force(self):
        repository = LocalCanonicalRepository()
        writer_a = repository.bootstrap()
        writer_b = repository.bootstrap()
        try:
            self.assertEqual(writer_a.identity.git_ref_sha, writer_b.identity.git_ref_sha)
            writer_a.connection.execute(
                "INSERT INTO beads_tasks(task_id, task_type, status, assignee, priority, created_at, ready, blocked, labels_json) "
                "VALUES ('writer-a','task','open',NULL,1,'2026-08-15T00:00:00Z',1,0,'[]')"
            )
            writer_b.connection.execute(
                "INSERT INTO beads_tasks(task_id, task_type, status, assignee, priority, created_at, ready, blocked, labels_json) "
                "VALUES ('writer-b','task','open',NULL,1,'2026-08-15T00:00:00Z',1,0,'[]')"
            )
            repository.publish(writer_a.identity.git_ref_sha, writer_a)
            with self.assertRaises(StaleCanonicalBase):
                repository.publish(writer_b.identity.git_ref_sha, writer_b)
            self.assertFalse(repository.force_attempted)
        finally:
            writer_a.close()
            writer_b.close()

    def test_scenario_7_failed_push_creates_no_allocation(self):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, [task("task-fail-push")])
        before = repository.identity
        repository.fail_next_pushes(1)
        service = AllocationService(repository, clock=lambda: "2026-08-15T00:00:00Z")
        result = service.process(command("s7", "ALLOCATE_TASK", task_id="task-fail-push"), context(701))
        self.assertEqual((result.status, result.reason_code), ("REJECTED", "CANONICAL_PUSH_FAILED"))
        self.assertEqual(repository.identity, before)
        self.assertEqual(row_count(repository, "allocations"), 0)

    def test_scenario_12_release_preserves_history_and_clears_active_uniqueness(self):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, [task("task-release")])
        service = AllocationService(repository, clock=lambda: "2026-08-15T00:00:00Z")
        granted = service.process(command("s12-grant", "ALLOCATE_TASK", task_id="task-release"), context(1201))
        self.assertEqual(granted.status, "ALLOCATED")
        release = service.process(
            command(
                "s12-release",
                "RELEASE",
                allocation_id=granted.allocation_id,
                reason="bounded Workstream D fixture",
            ),
            context(1202),
        )
        self.assertEqual(release.status, "RELEASED")
        self.assertEqual(row_count(repository, "active_task_allocations"), 0)
        self.assertEqual(row_count(repository, "allocations"), 1)
        connection = repository.inspect()
        try:
            state = connection.execute(
                "SELECT state FROM allocations WHERE allocation_id = ?",
                (granted.allocation_id,),
            ).fetchone()[0]
            event_count = connection.execute(
                "SELECT COUNT(*) FROM allocation_events WHERE allocation_id = ?",
                (granted.allocation_id,),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(state, "RELEASED")
        self.assertGreaterEqual(int(event_count), 2)


if __name__ == "__main__":
    unittest.main()
