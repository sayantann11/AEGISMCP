from click.testing import CliRunner
import httpx
import pytest

from aegismcp.cli import main
from aegismcp.config import get_setting
from proxy_server import create_app


def test_sutraksh_environment_value_has_precedence(monkeypatch):
    monkeypatch.setenv("SUTRAKSH_REDIS_HOST", "sutraksh-host")
    monkeypatch.setenv("AEGIS_REDIS_HOST", "legacy-host")
    monkeypatch.setenv("REDIS_HOST", "generic-host")

    assert get_setting("AEGIS_REDIS_HOST", "default-host", "REDIS_HOST") == "sutraksh-host"


def test_legacy_aegis_environment_value_is_supported(monkeypatch):
    monkeypatch.delenv("SUTRAKSH_MODE", raising=False)
    monkeypatch.setenv("AEGIS_MODE", "warn")

    assert get_setting("AEGIS_MODE", "enforce") == "warn"


def test_generic_environment_alias_is_supported(monkeypatch):
    monkeypatch.delenv("SUTRAKSH_AES_KEY_B64", raising=False)
    monkeypatch.delenv("AEGIS_AES_KEY_B64", raising=False)
    monkeypatch.setenv("AES_KEY_B64", "legacy-generic-key")

    assert get_setting("SUTRAKSH_AES_KEY_B64", None,
                       "AEGIS_AES_KEY_B64", "AES_KEY_B64") == "legacy-generic-key"


def test_default_is_used_if_no_environment_value_is_set(monkeypatch):
    monkeypatch.delenv("SUTRAKSH_ENV_FILE", raising=False)
    monkeypatch.delenv("AEGIS_ENV_FILE", raising=False)

    assert get_setting("AEGIS_ENV_FILE", ".env.redis") == ".env.redis"


def test_cli_help_is_available_under_new_and_legacy_command_names():
    runner = CliRunner()
    for command_name in ("sutraksh", "aegismcp"):
        result = runner.invoke(main, ["--help"], prog_name=command_name)
        assert result.exit_code == 0
        assert "proxy" in result.output
        assert "Sutraksh AI security and governance infrastructure." in result.output


def test_cli_prefers_sutraksh_environment_over_legacy_aegis(monkeypatch):
    import os
    import uvicorn

    captured = {}

    def fake_run(_app, **kwargs):
        captured.update(kwargs)
        captured["upstream"] = os.environ["SUTRAKSH_UPSTREAM_BASE_URL"]
        captured["provider"] = os.environ["SUTRAKSH_UPSTREAM_PROVIDER"]
        captured["mode"] = os.environ["SUTRAKSH_MODE"]
        captured["env_file"] = os.environ["SUTRAKSH_ENV_FILE"]

    monkeypatch.setattr(uvicorn, "run", fake_run)
    result = CliRunner().invoke(main, ["proxy"], prog_name="sutraksh", env={
        "SUTRAKSH_UPSTREAM_BASE_URL": "https://new-provider.example/v1",
        "AEGIS_UPSTREAM_BASE_URL": "https://old-provider.example/v1",
        "SUTRAKSH_UPSTREAM_PROVIDER": "ollama",
        "AEGIS_UPSTREAM_PROVIDER": "anthropic",
        "SUTRAKSH_MODE": "warn",
        "AEGIS_MODE": "enforce",
        "SUTRAKSH_PROXY_HOST": "0.0.0.0",
        "AEGIS_PROXY_HOST": "127.0.0.1",
        "SUTRAKSH_PROXY_PORT": "9001",
        "AEGIS_PROXY_PORT": "9002",
        "SUTRAKSH_ENV_FILE": ".sutraksh.env",
        "AEGIS_ENV_FILE": ".aegis.env",
    })

    assert result.exit_code == 0, result.output
    assert "Starting Sutraksh proxy" in result.output
    assert captured["upstream"] == "https://new-provider.example/v1"
    assert captured["provider"] == "ollama"
    assert captured["mode"] == "warn"
    assert captured["env_file"] == ".sutraksh.env"
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 9001


@pytest.mark.asyncio
async def test_proxy_prefers_sutraksh_environment_over_legacy_aegis(monkeypatch):
    monkeypatch.setenv("SUTRAKSH_UPSTREAM_BASE_URL", "https://new-provider.example/v1")
    monkeypatch.setenv("AEGIS_UPSTREAM_BASE_URL", "https://old-provider.example/v1")
    monkeypatch.setenv("SUTRAKSH_UPSTREAM_PROVIDER", "ollama")
    monkeypatch.setenv("AEGIS_UPSTREAM_PROVIDER", "anthropic")
    monkeypatch.setenv("SUTRAKSH_MODE", "warn")
    monkeypatch.setenv("AEGIS_MODE", "enforce")
    captured = {}

    def upstream_handler(request):
        captured["url"] = str(request.url)
        captured["payload"] = request.read().decode("utf-8")
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "mock response"}}],
        })

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(upstream_client=upstream)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                base_url="http://sutraksh.test") as client:
        response = await client.post("/v1/chat/completions", json={
            "messages": [{"role": "user", "content": "sk-fake-test-key-123456789012345"}],
        })
    await upstream.aclose()

    assert response.status_code == 200
    assert captured["url"] == "https://new-provider.example/v1/chat/completions"
    # Warn mode intentionally forwards the original content unchanged.
    assert "sk-fake-test-key-123456789012345" in captured["payload"]
