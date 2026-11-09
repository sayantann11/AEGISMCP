"""Opt-in integration test against the locally running TLS Redis container."""

import os
import base64
from pathlib import Path
import unittest
import uuid

from aegismcp.crypto import MappingCipher
from aegismcp.detectors import PatternDetector
from aegismcp.engine import TokenizationEngine
from aegismcp.redis_vault import RedisTokenVault, create_tls_redis_client
from aegismcp.vault import VaultError


ROOT = Path(__file__).resolve().parents[1]


def load_env_file(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def setting(values: dict[str, str], name: str, *aliases: str) -> str:
    for key in (name, *aliases):
        if key in values:
            return values[key]
    raise KeyError(name)


@unittest.skipUnless(os.getenv("SUTRAKSH_LIVE_REDIS", os.getenv("AEGIS_LIVE_REDIS")) == "1",
                     "set SUTRAKSH_LIVE_REDIS=1 to run the live Redis test (legacy: AEGIS_LIVE_REDIS)")
class LiveRedisFlowTests(unittest.TestCase):
    def test_sensitive_value_is_encrypted_stored_and_restored(self):
        env = load_env_file(ROOT / ".env.redis")
        # Compose's private test runner overrides host/port so the test uses
        # service DNS on the isolated Docker network, never host networking.
        for name, aliases in (
            ("SUTRAKSH_REDIS_HOST", ("AEGIS_REDIS_HOST", "REDIS_HOST")),
            ("SUTRAKSH_REDIS_PORT", ("AEGIS_REDIS_PORT", "REDIS_PORT")),
            ("SUTRAKSH_REDIS_USERNAME", ("AEGIS_REDIS_USERNAME", "REDIS_USERNAME")),
            ("SUTRAKSH_REDIS_PASSWORD", ("AEGIS_REDIS_PASSWORD", "REDIS_PASSWORD")),
        ):
            for candidate in (name, *aliases):
                if os.getenv(candidate):
                    env[name] = os.environ[candidate]
                    break
        tls = ROOT / "secrets" / "redis-tls"
        client = create_tls_redis_client(
            host=setting(env, "SUTRAKSH_REDIS_HOST", "AEGIS_REDIS_HOST", "REDIS_HOST"),
            port=int(setting(env, "SUTRAKSH_REDIS_PORT", "AEGIS_REDIS_PORT", "REDIS_PORT")),
            username=setting(env, "SUTRAKSH_REDIS_USERNAME", "AEGIS_REDIS_USERNAME", "REDIS_USERNAME"),
            password=setting(env, "SUTRAKSH_REDIS_PASSWORD", "AEGIS_REDIS_PASSWORD", "REDIS_PASSWORD"),
            ca_certs=str(tls / "ca.crt"), client_cert=str(tls / "client.crt"),
            client_key=str(tls / "client.key"),
        )
        vault = RedisTokenVault(
            client, MappingCipher.from_base64(setting(
                env, "SUTRAKSH_AES_KEY_B64", "AEGIS_AES_KEY_B64", "AES_KEY_B64")),
            index_key=base64.b64decode(setting(
                env, "SUTRAKSH_INDEX_KEY_B64", "AEGIS_INDEX_KEY_B64", "INDEX_KEY_B64"), validate=True),
            ttl_seconds=300,
        )
        tenant = "integration-tenant"
        session = str(uuid.uuid4())
        secret = "sk-live-test-123456789012345678901234"
        engine = TokenizationEngine(PatternDetector(), vault)
        try:
            sanitized = engine.tokenize(f"Use API key {secret}", session, tenant_id=tenant)
            self.assertNotIn(secret, sanitized.sanitized_text)
            self.assertIn("[API_KEY_01]", sanitized.sanitized_text)
            redis_key = vault._key(vault._scope(tenant, session, "[API_KEY_01]"))
            raw_payload = client.get(redis_key)
            self.assertIsNotNone(raw_payload)
            self.assertNotIn(secret.encode(), raw_payload)
            remaining_ttl = client.pttl(redis_key)
            self.assertGreater(remaining_ttl, 0)
            self.assertLessEqual(remaining_ttl, 300_000)
            with self.assertRaises(VaultError):
                vault.get(session, "[API_KEY_01]", tenant_id="another-tenant")

            llm_response = "Key accepted: [API_KEY_01]"
            restored = engine.restore(llm_response, session, tenant_id=tenant)
            self.assertEqual(restored, f"Key accepted: {secret}")
        finally:
            vault.delete(session, "[API_KEY_01]", tenant_id=tenant)
            client.close()


if __name__ == "__main__":
    unittest.main()
