"""Command-line entry point for AEGISMCP."""

from __future__ import annotations

import os

import click


@click.group()
@click.version_option(package_name="aegismcp")
def main() -> None:
    """Developer-first security and privacy proxy for AI workflows."""


@main.command("proxy")
@click.option("--host", default=lambda: os.getenv("AEGIS_PROXY_HOST", "127.0.0.1"), show_default=True)
@click.option("--port", type=click.IntRange(1, 65535),
              default=lambda: int(os.getenv("AEGIS_PROXY_PORT", "8000")), show_default=True)
@click.option("--upstream-base-url", envvar="AEGIS_UPSTREAM_BASE_URL",
              help="Provider URL, for example https://api.openai.com/v1.")
@click.option("--provider", type=click.Choice(["openai", "anthropic", "ollama"], case_sensitive=False),
              default=lambda: os.getenv("AEGIS_UPSTREAM_PROVIDER", "openai"), show_default=True)
@click.option("--mode", type=click.Choice(["enforce", "warn"], case_sensitive=False),
              default=lambda: os.getenv("AEGIS_MODE", "enforce"), show_default=True)
@click.option("--env-file", envvar="AEGIS_ENV_FILE", default=".env.redis", show_default=True,
              help="Local file containing Redis and vault settings.")
@click.option("--reload", is_flag=True, help="Enable Uvicorn auto-reload for local development.")
def proxy(host: str, port: int, upstream_base_url: str | None, provider: str,
          mode: str, env_file: str, reload: bool) -> None:
    """Start the local OpenAI-compatible proxy server."""
    if upstream_base_url:
        os.environ["AEGIS_UPSTREAM_BASE_URL"] = upstream_base_url
    os.environ["AEGIS_UPSTREAM_PROVIDER"] = provider.lower()
    os.environ["AEGIS_MODE"] = mode.lower()
    os.environ["AEGIS_ENV_FILE"] = env_file

    if not os.getenv("AEGIS_UPSTREAM_BASE_URL"):
        raise click.UsageError("set --upstream-base-url or AEGIS_UPSTREAM_BASE_URL")

    import uvicorn

    click.echo(f"Starting AEGISMCP proxy on http://{host}:{port} ({mode} mode, {provider} upstream)")
    uvicorn.run("proxy_server:app", host=host, port=port, reload=reload)
