# Sutraksh

### AI Security & Governance Infrastructure

**Built in India. Securing AI Everywhere.**

Sutraksh is a local-first AI privacy and security proxy that helps developers protect sensitive information before it reaches external AI model providers. It detects selected sensitive information, replaces it with scoped placeholders, stores temporary mappings using authenticated encryption, and restores authorized values in model responses inside the trusted proxy.

> Phase 1 is an alpha prototype. Review the security notes below before using it with real data.

## What is Sutraksh?

Sutraksh is an OpenAI-compatible local proxy for AI workflows. Its current Phase 1 alpha focuses on detecting common secrets and personal data in chat messages, sanitizing those messages before upstream transmission, and restoring recognized placeholders locally in the model response.

## Why Sutraksh?

Prompts can accidentally include API keys, credentials, or personal information. Once sent to an external model, that content has left the developer's environment. Sutraksh aims to reduce that exposure while preserving prompt context: the model sees placeholders such as `[API_KEY_01]`, and the trusted proxy can restore them in the response.

## Key Features

The default detector runs locally and offline. Its rules cover common provider keys and tokens (OpenAI-style, AWS access keys, GitHub, GitLab, Slack, Stripe, Google API keys), bearer and Basic-auth credentials, JWTs, private-key blocks, labeled passwords/secrets, one-time/PIN codes, and credentials embedded in database or web URLs. It also checks for email addresses, phone numbers, payment cards (with Luhn validation), IBANs (with MOD-97 validation), UPI IDs, IP and MAC addresses, and labeled government IDs, dates of birth, and street addresses. India-specific rules include Aadhaar, PAN, and GSTIN formats; additional labeled rules cover identifiers such as SSNs, ITINs, passports, and driver's licenses.

To add local name and location recognition plus Presidio's larger regional recognizer set, install the optional PII extra and its small English spaCy model:

```powershell
python -m pip install -e ".[pii]"
python -m spacy download en_core_web_sm
$env:SUTRAKSH_PII_ENGINE = 'presidio'
sutraksh proxy --upstream-base-url https://api.openai.com/v1
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

## Installation

The PyPI distribution name remains `aegis-privacy-proxy` because version 0.1.0 has already been published. That published version uses the legacy `aegismcp` command. The current source prepares version 0.1.1 with the new `sutraksh` command; this rebranding task does not publish that release.

Install the currently published version with:

```powershell
python -m pip install aegis-privacy-proxy
```

The preferred CLI in the current source is `sutraksh`; the `aegismcp` command and Python import namespace remain available for backward compatibility. To run the current source with the new command, or to run the local Docker Redis setup and examples, clone the source repository:

```powershell
git clone https://github.com/sayantann11/sutraksh.git
cd sutraksh
python -m pip install -e .
```

## Architecture Overview

The trusted local proxy separates detection, tokenization, encryption, Redis storage, provider adaptation, and response restoration. See the [architecture and design specification](docs/ARCHITECTURE.md) for the component map, data flows, configuration, and current production gaps.

## How It Works

1. The proxy scans chat-message strings locally.
2. Detected values are replaced with scoped placeholders and encrypted mappings are stored in Redis with a short TTL.
3. The sanitized request is sent to the configured provider.
4. Recognized placeholders in the response are resolved and restored locally before delivery.

Redis, the proxy process, its keys, and restored values are inside the trusted boundary. If protection or restoration fails in `enforce` mode, the proxy blocks or withholds the affected request/response.

## Quick Start

Requirements: Python 3.10+, Docker Desktop with Compose, and the repository checkout.

1. **Prepare and start ephemeral local Redis.** Generate local TLS/ACL credentials once, then start Redis:

   ```powershell
   python scripts/prepare_live_redis.py
   docker compose up -d
   ```

   Keep the generated `.env.redis`, `docker/users.acl`, and `secrets/redis-tls/` files private. If you have already generated them, skip the setup script.

2. **Install Sutraksh and its CLI.** A virtual environment is recommended:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -e .
   ```

3. **Start the proxy.** Configure an upstream URL and provider first. For the local mock demo, use the URL below; for a real provider, set its API base URL instead.

   ```powershell
   sutraksh proxy --upstream-base-url http://127.0.0.1:8101/v1
   ```

The proxy listens on `http://127.0.0.1:8000`. In a second terminal, run the no-provider-key demo:

```powershell
python examples/chat_test.py
```

The example starts a mock upstream, prints the sanitized prompt it receives, and then prints the response after local restoration. It uses only a fake key and does not call an external model.

## Supported Providers

The proxy exposes OpenAI-compatible `POST /v1/chat/completions` ingress and supports these upstreams:

- **OpenAI:** compatible chat completions endpoint, using `X-Upstream-Api-Key`.
- **Ollama:** local OpenAI-compatible chat completions endpoint; no provider key is required.
- **Anthropic:** a basic adapter translates the supported OpenAI chat subset to the Anthropic Messages API. Native Anthropic SDK `/v1/messages` ingress is not implemented.

Streaming (`stream: true`) is supported for the OpenAI-compatible response format, including the Anthropic adapter's supported events. Provider-specific advanced fields may not translate losslessly.

### OpenAI SDK example

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

## Configuration

The proxy reads Redis and vault settings from `.env.redis` by default. Common settings can also be supplied as environment variables or CLI options:

```powershell
$env:SUTRAKSH_UPSTREAM_PROVIDER = 'openai' # openai, anthropic, or ollama
$env:SUTRAKSH_MODE = 'enforce'              # enforce or warn
$env:SUTRAKSH_UPSTREAM_BASE_URL = 'https://api.openai.com/v1'
sutraksh proxy
```

Use `SUTRAKSH_*` variables for new deployments. Existing `AEGIS_*` variables remain supported; when both are set, the `SUTRAKSH_*` value wins. Existing generic variables such as `REDIS_HOST`, `AES_KEY_B64`, and `INDEX_KEY_B64` remain as last-resort aliases for older local `.env.redis` files.

| Setting | Purpose | Default |
| --- | --- | --- |
| `SUTRAKSH_UPSTREAM_BASE_URL` | Upstream API base URL. | Required |
| `SUTRAKSH_UPSTREAM_PROVIDER` | `openai`, `anthropic`, or `ollama`. | `openai` |
| `SUTRAKSH_MODE` | `enforce` or `warn`. | `enforce` |
| `SUTRAKSH_PROXY_HOST`, `SUTRAKSH_PROXY_PORT` | Local proxy bind address and port. | `127.0.0.1`, `8000` |
| `SUTRAKSH_ENV_FILE` | Local development environment file. | `.env.redis` |
| `SUTRAKSH_AES_KEY_B64`, `SUTRAKSH_INDEX_KEY_B64` | AES-256-GCM key and HMAC index key, base64 encoded. | Required in enforce mode |
| `SUTRAKSH_REDIS_HOST`, `SUTRAKSH_REDIS_PORT` | Redis endpoint. | `127.0.0.1`, `6380` |
| `SUTRAKSH_REDIS_USERNAME`, `SUTRAKSH_REDIS_PASSWORD` | Redis ACL credentials. | Required in enforce mode |
| `SUTRAKSH_REDIS_TLS_DIR` | Directory containing the local CA/client certificate and key. | `secrets/redis-tls/` |
| `SUTRAKSH_VAULT_TTL_SECONDS` | Mapping lifetime, restricted to 300–900 seconds. | `600` |
| `SUTRAKSH_PII_ENGINE` | `pattern` or optional local `presidio` detector. | `pattern` |
| `SUTRAKSH_TENANT_ID` | Static tenant scope for this proxy process. | `local-dev` |

Individual TLS paths can be set with `SUTRAKSH_REDIS_CA_CERTS`, `SUTRAKSH_REDIS_CLIENT_CERT`, and `SUTRAKSH_REDIS_CLIENT_KEY`. Use `X-Upstream-Api-Key` to pass the real OpenAI or Anthropic credential on each request. The `sutraksh` command accepts `--provider`, `--mode`, `--host`, `--port`, and `--env-file`. `aegismcp` remains an alias for the CLI. In `enforce` mode, tokenization and restoration errors fail closed. `warn` mode logs detected entity categories/counts and forwards original content unchanged; use it only with synthetic data.

## Security Architecture

- Regex and pattern-based detectors are experimental. They can miss sensitive values and produce false positives; names in particular are not reliably identified by regex alone.
- Optional Presidio detection runs locally when installed and enabled; it adds coverage but does not make detection exhaustive. The default detector remains offline and rule-based.
- The local Compose setup publishes Redis only on `127.0.0.1:6380` so a host-installed proxy can reach it; it uses TLS/mTLS, ACLs, in-memory operation, and strict TTLs. Do not bind Redis to public interfaces. In production, place Redis on a private network beside the proxy. The Compose setup is a development example, not a production deployment blueprint.
- Sutraksh is not a substitute for access control, secret management, or data-loss prevention. Audit detector behavior, proxy configuration, tenant identity handling, and failure modes before production use.
- The proxy process is inside the trusted boundary. Python cannot reliably zeroize immutable plaintext or key objects in memory.
- The Redis integration uses ACL authentication, ciphertext values, HMAC-derived key names, and atomic key TTLs.

## Development and Testing

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

## Current Limitations

- Sutraksh is a Phase 1 alpha. Pattern rules and optional local NER can miss sensitive data or produce false positives; this is not a production-certified DLP guarantee.
- Token mappings are scoped to one HTTP request in the current proxy. Conversation-wide placeholder continuity is not implemented.
- The proxy does not authenticate callers or resolve tenant identity from an identity provider. `SUTRAKSH_TENANT_ID` is a static process setting; do not expose a shared instance to multiple users without trusted authentication and tenant middleware.
- Only recognized placeholders from the request are restored. New sensitive information generated by a model is not automatically detected or redacted.
- Native Anthropic SDK `/v1/messages` ingress, an MCP tool-call firewall, allow/deny tool policies, human approvals, and an MCP audit service are not implemented.
- `/healthz` confirms that the proxy process responds; it does not test Redis or provider connectivity.

## Roadmap

Potential follow-on work, subject to design and validation:

- Authenticated tenant and user identity resolution.
- Native provider interfaces and broader provider compatibility coverage.
- Output-side sensitive-data detection and richer policy controls.
- MCP tool-call inspection, allow/deny policies, approval workflows, and minimized audit events.

These are roadmap ideas; they are not implemented in the current release.

## Contributing

Contributions are welcome. Please open an issue or pull request at [github.com/sayantann11/sutraksh](https://github.com/sayantann11/sutraksh). Run the local test suite before proposing changes:

```powershell
python -m pip install -e ".[test]"
python -m pytest
```

For design context and implementation boundaries, start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Please do not include real credentials, `.env` files, certificates, private keys, or generated Redis ACLs in commits.

## License

Sutraksh is released under the [MIT License](LICENSE). The existing copyright attribution is retained.

## Architecture handoff

For the system overview, request lifecycle, security boundaries, configuration reference, and current implementation gaps, see the [architecture and design specification](docs/ARCHITECTURE.md).
