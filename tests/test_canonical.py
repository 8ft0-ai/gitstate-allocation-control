import unittest

from phase2.canonical import (
    CANONICAL_REF,
    CanonicalIdentity,
    CanonicalIdentityMismatch,
    LocalCanonicalRepository,
    NoForceCASPublisher,
    StaleCanonicalBase,
    verify_canonical_identity,
)


class CanonicalTests(unittest.TestCase):
    def test_bootstrap_verifies_ref_git_and_dolt_identities(self):
        valid = CanonicalIdentity(CANONICAL_REF, "a" * 40, "dolt-1")
        verify_canonical_identity(valid, expected_git_sha="a" * 40, expected_dolt_commit="dolt-1")
        cases = [
            CanonicalIdentity("refs/heads/main", "a" * 40, "dolt-1"),
            CanonicalIdentity(CANONICAL_REF, "not-a-sha", "dolt-1"),
            CanonicalIdentity(CANONICAL_REF, "a" * 40, ""),
        ]
        for identity in cases:
            with self.subTest(identity=identity), self.assertRaises(CanonicalIdentityMismatch):
                verify_canonical_identity(identity)

    def test_expected_old_sha_rejects_stale_snapshot(self):
        repository = LocalCanonicalRepository()
        first = repository.bootstrap()
        second = repository.bootstrap()
        repository.publish(first.identity.git_ref_sha, first)
        with self.assertRaises(StaleCanonicalBase):
            repository.publish(second.identity.git_ref_sha, second)
        first.close()
        second.close()
        self.assertFalse(repository.force_attempted)

    def test_no_force_cas_checks_expected_old_before_push(self):
        pushed = []
        current = {CANONICAL_REF: "a" * 40}
        publisher = NoForceCASPublisher(
            lambda ref: current[ref],
            lambda ref, candidate: pushed.append((ref, candidate)),
        )
        publisher.publish(CANONICAL_REF, "a" * 40, "b" * 40)
        self.assertEqual(pushed, [(CANONICAL_REF, "b" * 40)])
        with self.assertRaises(StaleCanonicalBase):
            publisher.publish(CANONICAL_REF, "c" * 40, "d" * 40)
        self.assertEqual(len(pushed), 1)


if __name__ == "__main__":
    unittest.main()
