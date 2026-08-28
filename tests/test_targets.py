import socket
import unittest

from aegisscan.targets import TargetPolicyError, enforce_authorization, expand_targets


class TargetTests(unittest.TestCase):
    def test_expands_and_deduplicates_cidr(self) -> None:
        targets = expand_targets(["127.0.0.0/30", "127.0.0.1"])
        self.assertEqual([item.address for item in targets], ["127.0.0.1", "127.0.0.2"])
        self.assertTrue(all(item.family == socket.AF_INET for item in targets))

    def test_marks_public_address(self) -> None:
        self.assertTrue(expand_targets(["8.8.8.8"])[0].is_public)
        self.assertEqual(expand_targets(["8.8.8.8"])[0].network_scope, "public")

    def test_classifies_loopback_scope(self) -> None:
        self.assertEqual(expand_targets(["127.0.0.1"])[0].network_scope, "loopback")

    def test_requires_authorization(self) -> None:
        targets = expand_targets(["127.0.0.1"])
        with self.assertRaisesRegex(TargetPolicyError, "Authorization"):
            enforce_authorization(targets, authorized=False, allow_public=False)

    def test_public_target_requires_separate_opt_in(self) -> None:
        targets = expand_targets(["8.8.8.8"])
        with self.assertRaisesRegex(TargetPolicyError, "Public targets"):
            enforce_authorization(targets, authorized=True, allow_public=False)
        enforce_authorization(targets, authorized=True, allow_public=True)

    def test_rejects_large_scope(self) -> None:
        with self.assertRaisesRegex(TargetPolicyError, "too large"):
            expand_targets(["10.0.0.0/16"])


if __name__ == "__main__":
    unittest.main()
