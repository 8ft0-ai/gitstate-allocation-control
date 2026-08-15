import hashlib
import subprocess
import unittest

from phase2.adversarial import (
    AdversarialContractError,
    AssertionEvidence,
    AttemptNamespace,
    ClientTranscript,
    CONTROL_REPOSITORY_ID,
    EvidenceLedger,
    ExecutableIdentity,
    FaultEvidence,
    FinalOwnerEvidence,
    REQUIRED_DEPENDENCY_IDENTITIES,
    REQUIRED_EXECUTABLE_PATHS,
    SCENARIO_13_FAULT_CONTROLS,
    SCENARIO_IDS,
    STATE_REPOSITORY_ID,
    RepeatedResultEvidence,
    ScenarioDriver,
    ScenarioEvidence,
    TokenScopeEvidence,
    evidence_summary,
    scenario_by_id,
    scenario_catalogue,
    validate_live_gate,
)
from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.canonical import LocalCanonicalRepository, StaleCanonicalBase


def git_stdout(*args: str) -> str:
    return subprocess.check_output(("git", *args), text=True).strip()


TRUSTED_SHA = git_stdout("rev-parse", "HEAD")
PROTOCOL_SHA = "b" * 40
RUN_ID = 31880000000
RUN_ATTEMPT = 1
NAMESPACE = f"wd-{RUN_ID}-{RUN_ATTEMPT}-abc123"
AGENT = "agent://human/8ft0-ai/session/workstream-d"
DURABILITY = ("github_issue", "github_repository", "github_ref", "github_actions")
PROJECTION_DIGEST = hashlib.sha256(b"canonical-projection").hexdigest()
CLIENT_DIGEST = hashlib.sha256(b"clean-client-transcript").hexdigest()


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


def command(name, request_type, *, task_id=None, allocation_id=None, reason=None):
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


def token_scope(profile: str) -> TokenScopeEvidence:
    if profile == "control":
        repository_id = CONTROL_REPOSITORY_ID
        permissions = ("metadata:read", "contents:read", "issues:write")
    else:
        repository_id = STATE_REPOSITORY_ID
        permissions = ("metadata:read", "contents:write")
    return TokenScopeEvidence(
        profile=profile,
        requested_repository_ids=(repository_id,),
        returned_repository_ids=(repository_id,),
        requested_permissions=permissions,
        returned_permissions=permissions,
        restrictions_explicit=True,
        returned_scope_validated=True,
        cross_repository_denied=True,
    )


def executable_identities(trusted_sha: str = TRUSTED_SHA) -> tuple[ExecutableIdentity, ...]:
    identities = []
    for path in sorted(REQUIRED_EXECUTABLE_PATHS):
        tree_entry = git_stdout("ls-tree", TRUSTED_SHA, "--", path)
        blob = git_stdout("rev-parse", "--verify", f"{TRUSTED_SHA}:{path}")
        identities.append(
            ExecutableIdentity(
                path=path,
                blob_sha=blob,
                commit_sha=trusted_sha,
                trusted_tree_entry=tree_entry,
                tree_object_spec=f"{trusted_sha}:{path}",
            )
        )
    return tuple(identities)


def evidence_for(
    scenario_id: int,
    *,
    passed: bool = True,
    namespace: str = NAMESPACE,
    trusted_sha: str = TRUSTED_SHA,
    protocol_sha: str = PROTOCOL_SHA,
) -> ScenarioEvidence:
    spec = scenario_by_id(scenario_id)
    assertions = tuple(
        AssertionEvidence(assertion, passed, "protocol expectation", "matched")
        for assertion in spec.assertions
    )
    if scenario_id in {1, 2}:
        source_comments = (1000 + scenario_id * 10, 1001 + scenario_id * 10)
        canonical_count = 2
        projection_count = 2
    elif scenario_id == 3:
        source_comments = (1030, 1031, 1032)
        canonical_count = 3
        projection_count = 3
    else:
        source_comments = (
            (1000 + scenario_id,)
            if scenario_id in {8, 9, 11, 12, 13}
            else ()
        )
        canonical_count = 1 if scenario_id in {4, 5, 6, 7, 8, 9, 10, 12, 14} else 0
        projection_count = 1 if scenario_id in {4, 5, 8, 9, 11, 12, 14} else 0

    accepted_refs = tuple(f"{i + 2:040x}" for i in range(canonical_count))
    base_refs = tuple(f"{i + 1:040x}" for i in range(canonical_count))
    dolt_commits = tuple(f"dolt-accepted-{i + 1}" for i in range(canonical_count))
    canonical_rows = tuple(f"row-digest-{i + 1}" for i in range(canonical_count))
    projections = tuple(
        f"https://github.example/projection/{scenario_id}/{i + 1}"
        for i in range(projection_count)
    )
    accepted_ref = accepted_refs[-1] if accepted_refs else "2" * 40

    repeated_result = None
    if scenario_id == 4:
        repeated_result = RepeatedResultEvidence(
            request_id="01KWORKSTREAMDREPEATED0001",
            original_projection_sha256=PROJECTION_DIGEST,
            repeated_projection_sha256=PROJECTION_DIGEST,
            canonical_ref_before=accepted_ref,
            canonical_ref_after=accepted_ref,
            request_rows_before=1,
            request_rows_after=1,
            allocation_rows_before=1,
            allocation_rows_after=1,
        )
    final_owner = None
    if scenario_id == 6:
        final_owner = FinalOwnerEvidence(
            winning_allocation_id="allocation-winner",
            final_owner_allocation_id="allocation-winner",
            stale_allocation_id="allocation-stale",
            winning_ref_sha=accepted_ref,
            final_ref_sha=accepted_ref,
        )

    return ScenarioEvidence(
        scenario_id=scenario_id,
        attempt_namespace=namespace,
        trusted_sha=trusted_sha,
        protocol_sha=protocol_sha,
        workflow_run_id=RUN_ID,
        workflow_run_attempt=RUN_ATTEMPT,
        control_repository_id=CONTROL_REPOSITORY_ID,
        state_repository_id=STATE_REPOSITORY_ID,
        exit_status=0,
        source_comment_ids=source_comments,
        base_ref_shas=base_refs,
        accepted_ref_shas=accepted_refs,
        dolt_commits=dolt_commits,
        canonical_rows=canonical_rows,
        projection_urls=projections,
        fault_ids=tuple(
            FaultEvidence(
                control=control,
                identity=f"{namespace}:{scenario_id}:{control}",
                passed=True,
                expected_outcome=f"{control}:blocked-or-injected",
                actual_outcome=f"{control}:blocked-or-injected",
            )
            for control in spec.fault_controls
        ),
        assertions=assertions,
        client_transcripts=tuple(
            ClientTranscript(
                contract=contract,
                transcript_sha256=CLIENT_DIGEST,
                clean_environment=True,
            )
            for contract in spec.client_contracts
        ),
        executable_identities=executable_identities(trusted_sha),
        dependency_identities=REQUIRED_DEPENDENCY_IDENTITIES,
        durability_records=DURABILITY,
        repeated_result=repeated_result,
        final_owner=final_owner,
        installation_inventory_repository_ids=(
            (CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID) if scenario_id == 13 else ()
        ),
        installation_inventory_current=scenario_id == 13,
        installation_inventory_attestation=(
            "owner-audit:2026-08-15T08:00:00Z" if scenario_id == 13 else ""
        ),
        token_scope_records=(
            (token_scope("control"), token_scope("state")) if scenario_id == 13 else ()
        ),
        network_destinations=("api.github.com", "github.com") if scenario_id == 14 else (),
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

    def test_scenario_13_fault_controls_are_individual_not_umbrella(self):
        spec = scenario_by_id(13)
        self.assertEqual(spec.fault_controls, SCENARIO_13_FAULT_CONTROLS)
        self.assertGreaterEqual(len(spec.fault_controls), 20)
        self.assertNotIn("static_identity_negative", spec.fault_controls)
        self.assertNotIn("token_scope_negative", spec.fault_controls)

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

    def test_assertions_are_bound_one_to_one_to_protocol_requirements(self):
        evidence = evidence_for(4)
        mutated = ScenarioEvidence(**{**evidence.__dict__, "assertions": evidence.assertions[:-1]})
        with self.assertRaisesRegex(AdversarialContractError, "ASSERTION_BINDING_MISMATCH"):
            mutated.validate()

    def test_every_fault_control_requires_its_own_matching_attempt_bound_outcome(self):
        evidence = evidence_for(13)
        mutated = ScenarioEvidence(**{**evidence.__dict__, "fault_ids": evidence.fault_ids[:-1]})
        with self.assertRaisesRegex(AdversarialContractError, "FAULT_EVIDENCE_BINDING_MISMATCH"):
            mutated.validate()

        first = evidence.fault_ids[0]
        failed = FaultEvidence(
            control=first.control,
            identity=first.identity,
            passed=False,
            expected_outcome="blocked",
            actual_outcome="blocked",
        )
        with self.assertRaisesRegex(AdversarialContractError, "FAULT_OUTCOME_FAILED"):
            ScenarioEvidence(**{**evidence.__dict__, "fault_ids": (failed,) + evidence.fault_ids[1:]}).validate()

        mismatch = FaultEvidence(
            control=first.control,
            identity=first.identity,
            passed=True,
            expected_outcome="blocked",
            actual_outcome="unexpectedly-passed",
        )
        with self.assertRaisesRegex(AdversarialContractError, "FAULT_OUTCOME_MISMATCH"):
            ScenarioEvidence(**{**evidence.__dict__, "fault_ids": (mismatch,) + evidence.fault_ids[1:]}).validate()

        wrong_identity = FaultEvidence(
            control=first.control,
            identity=f"wd-{RUN_ID + 1}-1-other1:13:{first.control}",
            passed=True,
            expected_outcome=first.expected_outcome,
            actual_outcome=first.actual_outcome,
        )
        with self.assertRaisesRegex(AdversarialContractError, "FAULT_IDENTITY_NOT_ATTEMPT_BOUND"):
            ScenarioEvidence(**{**evidence.__dict__, "fault_ids": (wrong_identity,) + evidence.fault_ids[1:]}).validate()

    def test_scenarios_1_and_2_require_two_distinct_requests_and_results(self):
        for scenario_id in (1, 2):
            evidence = evidence_for(scenario_id)
            for override, code in (
                ({"source_comment_ids": evidence.source_comment_ids[:1]}, "SCENARIO_CONCURRENT_SOURCE_COUNT_MISMATCH"),
                ({"accepted_ref_shas": evidence.accepted_ref_shas[:1]}, "SCENARIO_CONCURRENT_ACCEPTED_REF_EVIDENCE_INCOMPLETE"),
                ({"dolt_commits": evidence.dolt_commits[:1]}, "SCENARIO_CONCURRENT_DOLT_EVIDENCE_INCOMPLETE"),
                ({"canonical_rows": evidence.canonical_rows[:1]}, "SCENARIO_CONCURRENT_CANONICAL_ROW_EVIDENCE_INCOMPLETE"),
                ({"projection_urls": evidence.projection_urls[:1]}, "SCENARIO_CONCURRENT_PROJECTION_COUNT_MISMATCH"),
            ):
                with self.subTest(scenario=scenario_id, code=code):
                    with self.assertRaisesRegex(AdversarialContractError, code):
                        ScenarioEvidence(**{**evidence.__dict__, **override}).validate()

    def test_scenario_3_requires_three_retained_requests_and_terminal_canonical_evidence(self):
        evidence = evidence_for(3)
        for override, code in (
            ({"source_comment_ids": evidence.source_comment_ids[:2]}, "SCENARIO_3_SOURCE_EVIDENCE_INCOMPLETE"),
            ({"accepted_ref_shas": evidence.accepted_ref_shas[:2]}, "SCENARIO_3_ACCEPTED_REF_EVIDENCE_INCOMPLETE"),
            ({"dolt_commits": evidence.dolt_commits[:2]}, "SCENARIO_3_DOLT_EVIDENCE_INCOMPLETE"),
            ({"canonical_rows": evidence.canonical_rows[:2]}, "SCENARIO_3_CANONICAL_ROW_EVIDENCE_INCOMPLETE"),
            ({"projection_urls": evidence.projection_urls[:2]}, "SCENARIO_3_PROJECTION_EVIDENCE_INCOMPLETE"),
        ):
            with self.assertRaisesRegex(AdversarialContractError, code):
                ScenarioEvidence(**{**evidence.__dict__, **override}).validate()

    def test_every_client_contract_requires_clean_typed_transcript(self):
        evidence = evidence_for(14)
        mutated = ScenarioEvidence(**{**evidence.__dict__, "client_transcripts": evidence.client_transcripts[:1]})
        with self.assertRaisesRegex(AdversarialContractError, "CLIENT_TRANSCRIPT_BINDING_MISMATCH"):
            mutated.validate()

    def test_executable_identities_are_bound_to_exact_trusted_tree_entries(self):
        evidence = evidence_for(1)
        original = next(e for e in evidence.executable_identities if e.path == "phase2/adversarial.py")
        remaining = tuple(e for e in evidence.executable_identities if e.path != original.path)

        wrong_commit = ExecutableIdentity(
            path=original.path,
            blob_sha=original.blob_sha,
            commit_sha="d" * 40,
            trusted_tree_entry=original.trusted_tree_entry,
            tree_object_spec=f"{'d' * 40}:{original.path}",
        )
        with self.assertRaisesRegex(AdversarialContractError, "EXECUTABLE_NOT_BOUND_TO_TRUSTED_COMMIT"):
            ScenarioEvidence(**{**evidence.__dict__, "executable_identities": (wrong_commit,) + remaining}).validate()

        wrong_tree_blob = ExecutableIdentity(
            path=original.path,
            blob_sha=original.blob_sha,
            commit_sha=TRUSTED_SHA,
            trusted_tree_entry=f"100644 blob {'c' * 40}\t{original.path}",
            tree_object_spec=f"{TRUSTED_SHA}:{original.path}",
        )
        with self.assertRaisesRegex(AdversarialContractError, "EXECUTABLE_BLOB_NOT_IN_TRUSTED_TREE"):
            ScenarioEvidence(**{**evidence.__dict__, "executable_identities": (wrong_tree_blob,) + remaining}).validate()

        fabricated_blob = "c" * 40
        fabricated_consistent = ExecutableIdentity(
            path=original.path,
            blob_sha=fabricated_blob,
            commit_sha=TRUSTED_SHA,
            trusted_tree_entry=f"100644 blob {fabricated_blob}\t{original.path}",
            tree_object_spec=f"{TRUSTED_SHA}:{original.path}",
        )
        with self.assertRaisesRegex(AdversarialContractError, "EXECUTABLE_TREE_ENTRY_NOT_FROM_TRUSTED_COMMIT"):
            ScenarioEvidence(
                **{
                    **evidence.__dict__,
                    "executable_identities": (fabricated_consistent,) + remaining,
                }
            ).validate()

        wrong_object_spec = ExecutableIdentity(
            path=original.path,
            blob_sha=original.blob_sha,
            commit_sha=TRUSTED_SHA,
            trusted_tree_entry=original.trusted_tree_entry,
            tree_object_spec=f"{TRUSTED_SHA}:wrong-path",
        )
        with self.assertRaisesRegex(AdversarialContractError, "EXECUTABLE_TREE_OBJECT_SPEC_MISMATCH"):
            ScenarioEvidence(**{**evidence.__dict__, "executable_identities": (wrong_object_spec,) + remaining}).validate()

        with self.assertRaisesRegex(AdversarialContractError, "INCOMPLETE_EXECUTABLE_INVENTORY"):
            ScenarioEvidence(**{**evidence.__dict__, "executable_identities": evidence.executable_identities[:1]}).validate()

    def test_dependency_identity_set_is_exact_and_complete(self):
        evidence = evidence_for(1)
        for dependencies in (
            REQUIRED_DEPENDENCY_IDENTITIES[:-1],
            REQUIRED_DEPENDENCY_IDENTITIES + ("unpinned",),
        ):
            with self.assertRaisesRegex(AdversarialContractError, "DEPENDENCY_IDENTITY_SET_MISMATCH"):
                ScenarioEvidence(**{**evidence.__dict__, "dependency_identities": dependencies}).validate()

    def test_scenario_4_requires_exact_repeated_projection_and_nonmutation(self):
        evidence = evidence_for(4)
        with self.assertRaisesRegex(AdversarialContractError, "MISSING_REPEATED_RESULT_EVIDENCE"):
            ScenarioEvidence(**{**evidence.__dict__, "repeated_result": None}).validate()
        bad = RepeatedResultEvidence(
            **{**evidence.repeated_result.__dict__, "repeated_projection_sha256": hashlib.sha256(b"different").hexdigest()}
        )
        with self.assertRaisesRegex(AdversarialContractError, "REPEATED_RESULT_PROJECTION_MISMATCH"):
            ScenarioEvidence(**{**evidence.__dict__, "repeated_result": bad}).validate()

    def test_scenario_6_requires_final_owner_to_match_winner_and_ref(self):
        evidence = evidence_for(6)
        with self.assertRaisesRegex(AdversarialContractError, "MISSING_FINAL_OWNER_EVIDENCE"):
            ScenarioEvidence(**{**evidence.__dict__, "final_owner": None}).validate()
        bad = FinalOwnerEvidence(**{**evidence.final_owner.__dict__, "final_owner_allocation_id": "allocation-stale"})
        with self.assertRaisesRegex(AdversarialContractError, "FINAL_OWNER_DOES_NOT_MATCH_WINNER"):
            ScenarioEvidence(**{**evidence.__dict__, "final_owner": bad}).validate()

    def test_scenario_13_requires_exact_inventory_and_token_scope(self):
        evidence = evidence_for(13)
        for override, code in (
            ({"installation_inventory_repository_ids": (CONTROL_REPOSITORY_ID,)}, "INSTALLATION_INVENTORY_MISMATCH"),
            ({"installation_inventory_current": False}, "STALE_OR_MISSING_INSTALLATION_INVENTORY"),
            ({"token_scope_records": evidence.token_scope_records[:1]}, "TOKEN_SCOPE_EVIDENCE_BINDING_MISMATCH"),
        ):
            with self.assertRaisesRegex(AdversarialContractError, code):
                ScenarioEvidence(**{**evidence.__dict__, **override}).validate()

    def test_token_scope_evidence_rejects_broader_or_cross_repository_access(self):
        evidence = evidence_for(13)
        bad_state = TokenScopeEvidence(
            profile="state",
            requested_repository_ids=(STATE_REPOSITORY_ID, CONTROL_REPOSITORY_ID),
            returned_repository_ids=(STATE_REPOSITORY_ID,),
            requested_permissions=("metadata:read", "contents:write"),
            returned_permissions=("metadata:read", "contents:write"),
            restrictions_explicit=True,
            returned_scope_validated=True,
            cross_repository_denied=True,
        )
        with self.assertRaisesRegex(AdversarialContractError, "TOKEN_REQUEST_REPOSITORY_SCOPE_MISMATCH"):
            ScenarioEvidence(**{**evidence.__dict__, "token_scope_records": (token_scope("control"), bad_state)}).validate()

    def test_scenario_14_requires_complete_github_durability_and_network_inventory(self):
        evidence = evidence_for(14)
        for override, code in (
            ({"durability_records": ()}, "MISSING_DURABILITY_EVIDENCE"),
            ({"durability_records": DURABILITY[:-1]}, "GITHUB_DURABILITY_INVENTORY_INCOMPLETE"),
            ({"network_destinations": ()}, "MISSING_NETWORK_DESTINATION_INVENTORY"),
        ):
            with self.assertRaisesRegex(AdversarialContractError, code):
                ScenarioEvidence(**{**evidence.__dict__, **override}).validate()

    def test_external_durable_service_is_rejected(self):
        evidence = evidence_for(14)
        with self.assertRaisesRegex(AdversarialContractError, "EXTERNAL_DURABLE_SERVICE_PRESENT"):
            ScenarioEvidence(**{**evidence.__dict__, "durability_records": evidence.durability_records + ("external_database",)}).validate()

    def test_driver_binds_backend_evidence_to_attempt_and_authorised_shas(self):
        namespace = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)

        class Backend:
            def __init__(self, evidence):
                self.evidence = evidence

            def execute(self, spec, attempt):
                return self.evidence

        with self.assertRaisesRegex(AdversarialContractError, "UNAUTHORISED_EVIDENCE_AUTHORITY"):
            ScenarioDriver(Backend(evidence_for(1, trusted_sha="d" * 40))).run(
                (1,), namespace, expected_trusted_sha=TRUSTED_SHA, expected_protocol_sha=PROTOCOL_SHA
            )
        other = f"wd-{RUN_ID + 1}-1-def456"
        with self.assertRaisesRegex(AdversarialContractError, "CROSS_ATTEMPT_EVIDENCE"):
            ScenarioDriver(Backend(evidence_for(1, namespace=other))).run(
                (1,), namespace, expected_trusted_sha=TRUSTED_SHA, expected_protocol_sha=PROTOCOL_SHA
            )

    def test_ledger_rejects_first_record_with_arbitrary_well_formed_authority(self):
        namespace = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)
        ledger = EvidenceLedger(namespace, expected_trusted_sha=TRUSTED_SHA, expected_protocol_sha=PROTOCOL_SHA)
        with self.assertRaisesRegex(AdversarialContractError, "UNAUTHORISED_EVIDENCE_AUTHORITY"):
            ledger.append(evidence_for(1, trusted_sha="d" * 40))

    def test_final_summary_revalidates_same_attempt_and_exact_authority(self):
        namespace = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)
        records = [evidence_for(scenario_id) for scenario_id in SCENARIO_IDS]
        summary = evidence_summary(
            records,
            attempt_namespace=namespace,
            expected_trusted_sha=TRUSTED_SHA,
            expected_protocol_sha=PROTOCOL_SHA,
        )
        self.assertTrue(summary["all_assertions_passed"])
        self.assertFalse(summary["external_durable_service_present"])
        self.assertFalse(summary["production_approval"])
        self.assertFalse(summary["workstream_e_authorised"])

        records[5] = evidence_for(6, protocol_sha="d" * 40)
        with self.assertRaisesRegex(AdversarialContractError, "UNAUTHORISED_EVIDENCE_AUTHORITY"):
            evidence_summary(
                records,
                attempt_namespace=namespace,
                expected_trusted_sha=TRUSTED_SHA,
                expected_protocol_sha=PROTOCOL_SHA,
            )

    def test_final_evidence_requires_all_fourteen_scenarios(self):
        namespace = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)
        records = [evidence_for(scenario_id) for scenario_id in SCENARIO_IDS[:-1]]
        with self.assertRaisesRegex(AdversarialContractError, "INCOMPLETE_WORKSTREAM_D_EVIDENCE"):
            evidence_summary(
                records,
                attempt_namespace=namespace,
                expected_trusted_sha=TRUSTED_SHA,
                expected_protocol_sha=PROTOCOL_SHA,
            )

    def test_driver_rejects_duplicate_scenario_and_backend_mismatch(self):
        namespace = AttemptNamespace.parse(NAMESPACE, run_id=RUN_ID, run_attempt=1)

        class Backend:
            def execute(self, spec, attempt):
                return evidence_for(1)

        driver = ScenarioDriver(Backend())
        with self.assertRaisesRegex(AdversarialContractError, "DUPLICATE_SCENARIO"):
            driver.run((1, 1), namespace, expected_trusted_sha=TRUSTED_SHA, expected_protocol_sha=PROTOCOL_SHA)
        with self.assertRaisesRegex(AdversarialContractError, "SCENARIO_EVIDENCE_MISMATCH"):
            driver.run((2,), namespace, expected_trusted_sha=TRUSTED_SHA, expected_protocol_sha=PROTOCOL_SHA)


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
