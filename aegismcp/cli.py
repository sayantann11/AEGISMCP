"""Sutraksh command-line entry point (legacy module path retained)."""

from __future__ import annotations

import os

import click

from .config import get_setting


@click.group()
@click.version_option(package_name="aegis-privacy-proxy")
def main() -> None:
    """Sutraksh AI security and governance infrastructure."""


@main.command("proxy")
@click.option("--host", envvar=["SUTRAKSH_PROXY_HOST", "AEGIS_PROXY_HOST"],
              default=lambda: get_setting("AEGIS_PROXY_HOST", "127.0.0.1"), show_default=True)
@click.option("--port", type=click.IntRange(1, 65535),
              envvar=["SUTRAKSH_PROXY_PORT", "AEGIS_PROXY_PORT"],
              default=lambda: int(get_setting("AEGIS_PROXY_PORT", "8000")), show_default=True)
@click.option("--upstream-base-url", envvar=["SUTRAKSH_UPSTREAM_BASE_URL", "AEGIS_UPSTREAM_BASE_URL"],
              help="Provider URL, for example https://api.openai.com/v1.")
@click.option("--provider", type=click.Choice(["openai", "anthropic", "ollama"], case_sensitive=False),
              envvar=["SUTRAKSH_UPSTREAM_PROVIDER", "AEGIS_UPSTREAM_PROVIDER"],
              default=lambda: get_setting("AEGIS_UPSTREAM_PROVIDER", "openai"), show_default=True)
@click.option("--mode", type=click.Choice(["enforce", "warn"], case_sensitive=False),
              envvar=["SUTRAKSH_MODE", "AEGIS_MODE"],
              default=lambda: get_setting("AEGIS_MODE", "enforce"), show_default=True)
@click.option("--env-file", envvar=["SUTRAKSH_ENV_FILE", "AEGIS_ENV_FILE"],
              default=lambda: get_setting("AEGIS_ENV_FILE", ".env.redis"), show_default=True,
              help="Local file containing Redis and vault settings.")
@click.option("--reload", is_flag=True, help="Enable Uvicorn auto-reload for local development.")
def proxy(host: str, port: int, upstream_base_url: str | None, provider: str,
          mode: str, env_file: str, reload: bool) -> None:
    """Start the local OpenAI-compatible proxy server."""
    if upstream_base_url:
        os.environ["SUTRAKSH_UPSTREAM_BASE_URL"] = upstream_base_url
    os.environ["SUTRAKSH_UPSTREAM_PROVIDER"] = provider.lower()
    os.environ["SUTRAKSH_MODE"] = mode.lower()
    os.environ["SUTRAKSH_ENV_FILE"] = env_file

    if not get_setting("AEGIS_UPSTREAM_BASE_URL"):
        raise click.UsageError("set --upstream-base-url or SUTRAKSH_UPSTREAM_BASE_URL (legacy: AEGIS_UPSTREAM_BASE_URL)")

    import uvicorn

    click.echo(f"Starting Sutraksh proxy on http://{host}:{port} ({mode} mode, {provider} upstream)")
    uvicorn.run("proxy_server:app", host=host, port=port, reload=reload)
