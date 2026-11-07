import time
import unittest

from aegismcp import InMemoryTokenVault, TokenizationEngine, VaultError
from aegismcp.detectors import PatternDetector


class TokenizationFlowTests(unittest.TestCase):
    def setUp(self):
        self.vault = InMemoryTokenVault(ttl_seconds=1)
        self.engine = TokenizationEngine(PatternDetector(known_names=["Rajesh Kumar"]), self.vault)

    def test_detect_sanitize_mock_llm_restore(self):
        prompt = "Summarize account for Rajesh Kumar, email rajesh@example.com, Aadhaar 2345-6789-0123; key sk-123456789012345678901234"
        safe = self.engine.tokenize(prompt, "tenant-a/session-1")
        self.assertNotIn("rajesh@example.com", safe.sanitized_text)
        self.assertNotIn("2345-6789-0123", safe.sanitized_text)
        self.assertNotIn("sk-123456789012345678901234", safe.sanitized_text)
        self.assertIn("[NAME_01]", safe.sanitized_text)

        # Mock LLM only sees sanitized input and returns its placeholders.
        mock_llm_response = "Account owner [NAME_01], contact [EMAIL_01]."
        final = self.engine.restore(mock_llm_response, "tenant-a/session-1")
        self.assertEqual(final, "Account owner Rajesh Kumar, contact rajesh@example.com.")

    def test_session_isolation(self):
        self.engine.tokenize("Contact bob@example.com", "tenant-a/session-1")
        with self.assertRaises(VaultError):
            self.engine.restore("Contact [EMAIL_01]", "tenant-b/session-1")

    def test_expired_token_fails_closed(self):
        self.engine.tokenize("Contact bob@example.com", "s1")
        time.sleep(1.05)
        with self.assertRaises(VaultError):
            self.engine.restore("Contact [EMAIL_01]", "s1")

    def test_missing_session_fails_closed(self):
        with self.assertRaises(VaultError):
            self.engine.tokenize("secret sk-123456789012345678901234", "")


if __name__ == "__main__":
    unittest.main()
