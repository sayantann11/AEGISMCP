# AEGISMCP

**Developer-first security and privacy proxy for AI workflows.**

AEGISMCP is an OpenAI-compatible local proxy that detects selected secrets and personal data, replaces them with scoped placeholders before forwarding prompts, and restores values in responses locally. Its encrypted Redis vault stores temporary mappings with a short TTL.

> Phase 1 is an alpha prototype. Review the security notes below before using it with real data.

## Why AEGISMCP

Prompts can accidentally include API keys, credentials, or personal information. Once sent to an external model, that content has left the developer's environment. AEGISMCP aims to reduce that exposure while preserving prompt context: the model sees placeholders such as `[API_KEY_01]`, and the trusted proxy can restore them in the response.

## Detection coverage

The default detector runs locally and offline. Its rules cover common provider keys and tokens (OpenAI-style, AWS access keys, GitHub, GitLab, Slack, Stripe, Google API keys), bearer and Basic-auth credentials, JWTs, private-key blocks, labeled passwords/secrets, one-time/PIN codes, and credentials embedded in database or web URLs. It also checks for email addresses, phone numbers, payment cards (with Luhn validation), IBANs (with MOD-97 validation), UPI IDs, IP and MAC addresses, and labeled government IDs, dates of birth, and street addresses. India-specific rules include Aadhaar, PAN, and GSTIN formats; additional labeled rules cover identifiers such as SSNs, ITINs, passports, and driver's licenses.

To add local name and location recognition plus Presidio's larger regional recognizer set, install the optional PII extra and its small English spaCy model:

```powershell
python -m pip install -e ".[pii]"
python -m spacy download en_core_web_sm
$env:AEGIS_PII_ENGINE = 'presidio'
aegismcp proxy --upstream-base-url https://api.openai.com/v1
```

Presidio combines patterns, checksums, context, and named-entity recognition, and supports custom recognizers and country-specific entities. Its supported entity list varies by release and locale; see the [Presidio supported entities](https://microsoft.github.io/presidio/supported_entities/) and [Analyzer documentation](https://microsoft.github.io/presidio/analyzer/). For programmatic use, exact names and organization-specific identifiers can be added locally:

```python
from aegismcp.detectors import PatternDetector

detector = PatternDetector(
    known_names=["Ada Lovelace"],
    custom_patterns={"EMPLOYEE_ID": r"\bEMP-\d{6}\b"},
)
```

No detector can find every sensitive fact in arbitrary text. Whether information identifies a person can depend on context and combinations of fields such as location and birth date, as NIST discusses in [SP 800-122](https://csrc.nist.gov/pubs/sp/800/122/final). Regex rules can miss unknown formats; NER can miss names or locations, especially across languages. The default mode does not send text to an external detection service. Test against your own data types and add organization-specific recognizers before relying on it.

## Quickstart

Requirements: Python 3.10+, Docker Desktop with Compose, and the repository checkout.

To install the published distribution from PyPI:

```powershell
python -m pip install aegis-privacy-proxy
```

1. **Prepare and start ephemeral local Redis.** Generate local TLS/ACL credentials once, then start Redis:

   ```powershell
   python scripts/prepare_live_redis.py
   docker compose up -d
   ```

   Keep the generated `.env.redis`, `docker/users.acl`, and `secrets/redis-tls/` files private. If you have already generated them, skip the setup script.

2. **Install AEGISMCP and its CLI.** A virtual environment is recommended:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -e .
   ```

3. **Start the proxy.** Configure an upstream URL and provider first. For the local mock demo, use the URL below; for a real provider, set its API base URL instead.

   ```powershell
   aegismcp proxy --upstream-base-url http://127.0.0.1:8101/v1
   ```

The proxy listens on `http://127.0.0.1:8000`. In a second terminal, run the no-provider-key demo:

```powershell
python examples/chat_test.py
```

The example starts a mock upstream, prints the sanitized prompt it receives, and then prints the response after local restoration. It uses only a fake key and does not call an external model.

## OpenAI-compatible client

Point an OpenAI SDK client at the local proxy. Keep the real provider credential in an environment variable; the proxy consumes `X-Upstream-Api-Key` and forwards it upstream.

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="proxy-placeholder",  # Required by the SDK; proxy does not use this value.
    default_headers={"X-Upstream-Api-Key": os.environ["MODEL_API_KEY"]},
)

result = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Summarize this text..."}],
)
print(result.choices[0].message.content)
```

The current ingress API is OpenAI-compatible `POST /v1/chat/completions`. OpenAI-compatible clients can use the proxy with OpenAI, Ollama, or the included basic Anthropic upstream adapter. The native Anthropic SDK `/v1/messages` ingress is not implemented; Anthropic upstream requests are made through AEGISMCP's OpenAI-compatible interface.

## Configuration

The proxy reads Redis and vault settings from `.env.redis` by default. Common settings can also be supplied as environment variables or CLI options:

```powershell
$env:AEGIS_UPSTREAM_PROVIDER = 'openai' # openai, anthropic, or ollama
$env:AEGIS_MODE = 'enforce'             # enforce or warn
$env:AEGIS_UPSTREAM_BASE_URL = 'https://api.openai.com/v1'
aegismcp proxy
```

You can also pass `--provider`, `--mode`, `--host`, `--port`, and `--env-file` to `aegismcp proxy`. In `enforce` mode, tokenization and restoration errors fail closed. `warn` mode logs detected entity categories/counts and forwards original content unchanged; use it only with synthetic data.

## Security notes and limitations

- Regex and pattern-based detectors are experimental. They can miss sensitive values and produce false positives; names in particular are not reliably identified by regex alone.
- Optional Presidio detection runs locally when installed and enabled; it adds coverage but does not make detection exhaustive. The default detector remains offline and rule-based.
- The local Compose setup publishes Redis only on `127.0.0.1:6380` so a host-installed proxy can reach it; it still requires TLS/mTLS, ACLs, in-memory operation, and strict TTLs. Do not bind Redis to public interfaces. In production, place Redis on a private network beside the proxy. The Compose setup is a development example, not a production deployment blueprint.
- AEGISMCP is not a substitute for access control, secret management, or data-loss prevention. Audit detector behavior, proxy configuration, tenant identity handling, and failure modes before production use.
- The proxy process is inside the trusted boundary. Python cannot reliably zeroize immutable plaintext or key objects in memory.
- Multi-tenant deployments need authenticated tenant identity middleware. Do not derive tenant identity from prompt text or an untrusted request field.

## Tests

Run unit and mocked-upstream tests locally with the test extra:

```powershell
python -m pip install -e ".[test]"
python -m pytest -q
```

To run the real optional name/location NER test, install the PII extra and English model first. The test skips when that optional model is not installed:

```powershell
python -m pip install -e ".[test,pii]"
python -m spacy download en_core_web_sm
python -m pytest -q tests/test_detectors.py
```

To include the TLS Redis integration test in the Compose environment:

```powershell
docker compose --profile test run --rm redis-test
```

Stop the local Redis service with `docker compose down` when finished.

## License

AEGISMCP is released under the [MIT License](LICENSE).

## Architecture handoff

For the system overview, request lifecycle, security boundaries, configuration reference, and current implementation gaps, see the [architecture and design specification](docs/ARCHITECTURE.md).
