import unittest

from aegismcp.crypto import MappingCipher
from aegismcp.detectors import PatternDetector
from aegismcp.engine import TokenizationEngine
from aegismcp.redis_vault import RedisTokenVault
from aegismcp.vault import VaultError


class FakeRedis:
    """Redis contract test double; retains bytes and records mandatory EX TTL."""
    def __init__(self):
        self.data = {}
        self.ttls = {}
        self.fail = False

    def set(self, key, value, *, ex):
        if self.fail:
            raise ConnectionError("redis unavailable")
        self.data[key] = value
        self.ttls[key] = ex
        return True

    def get(self, key):
        if self.fail:
            raise ConnectionError("redis unavailable")
        return self.data.get(key)

    def delete(self, key):
        self.data.pop(key, None)
        return 1


class RedisVaultFlowTests(unittest.TestCase):
    def setUp(self):
        self.redis = FakeRedis()
        self.vault = RedisTokenVault(
            self.redis, MappingCipher(b"k" * 32), index_key=b"i" * 32, ttl_seconds=300
        )
        self.engine = TokenizationEngine(PatternDetector(), self.vault)

    def test_encrypt_store_ttl_and_restore_flow(self):
        original = "sk-123456789012345678901234"
        result = self.engine.tokenize(f"Use API key {original}", "session-1", tenant_id="tenant-1")
        self.assertIn("[API_KEY_01]", result.sanitized_text)
        self.assertNotIn(original, result.sanitized_text)
        self.assertEqual(len(self.redis.data), 1)
        stored = next(iter(self.redis.data.values()))
        self.assertIsInstance(stored, bytes)
        self.assertNotIn(original.encode(), stored)
        self.assertEqual(next(iter(self.redis.ttls.values())), 300)

        # The mock model sees only the placeholder; restoration is local.
        response = self.engine.restore("Key received: [API_KEY_01]", "session-1", tenant_id="tenant-1")
        self.assertEqual(response, f"Key received: {original}")

    def test_tenant_isolation(self):
        self.vault.put("s", "[EMAIL_01]", "a@example.com", tenant_id="tenant-a")
        with self.assertRaises(VaultError):
            self.vault.get("s", "[EMAIL_01]", tenant_id="tenant-b")

    def test_redis_unavailable_fails_closed(self):
        self.redis.fail = True
        with self.assertRaises(VaultError):
            self.engine.tokenize("key sk-123456789012345678901234", "s", tenant_id="t")

    def test_rejects_ttl_outside_required_window(self):
        with self.assertRaises(ValueError):
            RedisTokenVault(self.redis, MappingCipher(b"k" * 32), index_key=b"i" * 32, ttl_seconds=60)


if __name__ == "__main__":
    unittest.main()
