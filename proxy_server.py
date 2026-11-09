"""Fail-closed, OpenAI-compatible LLM proxy for Sutraksh Phase 1.

The proxy buffers JSON responses and safely transforms SSE text/tool deltas.
It never forwards caller authorization/cookies and never logs prompt contents.
"""

from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
import re
import time
import uuid
from urllib.parse import urlsplit
from typing import Any, Iterator

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from aegismcp.crypto import MappingCipher
from aegismcp.config import get_setting
from aegismcp.detectors import PatternDetector
from aegismcp.engine import TokenizationEngine
from aegismcp.redis_vault import RedisTokenVault, create_tls_redis_client
from aegismcp.vault import InMemoryTokenVault


logger = logging.getLogger("sutraksh.proxy")
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_TOKEN_KIND = r"[A-Z][A-Z0-9_]{0,47}"
_PLACEHOLDER = re.compile(rf"\[(?:{_TOKEN_KIND})_\d{{2,}}\]")
_PARTIAL_PLACEHOLDER = re.compile(rf"\[(?:{_TOKEN_KIND})_\d*")


class StreamingPlaceholderRestorer:
    """Buffer possible token suffixes so markers split across SSE events stay private."""

    def __init__(self, engine: TokenizationEngine, session_id: str, tenant_id: str) -> None:
        self.engine = engine
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.pending: dict[tuple[Any, ...], str] = {}

    def _restore_safe(self, text: str) -> str:
        # A Redis lookup occurs only after a complete placeholder is assembled.
        # If Redis is unavailable or the mapping expired, the stream is aborted.
        return self.engine.restore(text, self.session_id, tenant_id=self.tenant_id)

    def push(self, key: tuple[Any, ...], fragment: str) -> str:
        buffered = self.pending.get(key, "") + fragment
        hold_from = None
        start = buffered.rfind("[")
        if start >= 0:
            suffix = buffered[start:]
            if _PARTIAL_PLACEHOLDER.fullmatch(suffix):
                hold_from = start
        if hold_from is None:
            self.pending.pop(key, None)
            return self._restore_safe(buffered)
        if len(buffered) - hold_from > 128:
            raise RuntimeError("placeholder fragment exceeded the safe buffer limit")
        self.pending[key] = buffered[hold_from:]
        return self._restore_safe(buffered[:hold_from])

    def flush(self, key: tuple[Any, ...]) -> str:
        pending = self.pending.pop(key, "")
        if pending and _PARTIAL_PLACEHOLDER.fullmatch(pending):
            raise RuntimeError("upstream ended in the middle of a placeholder")
        return self._restore_safe(pending)


def _sse_json(payload: dict[str, Any]) -> str:
    return "data: " + json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n\n"


async def _stream_openai_events(response: httpx.Response, restorer: StreamingPlaceholderRestorer | None):
    """Forward OpenAI-compatible SSE while restoring only complete safe fragments."""
    shell = {"id": "", "object": "chat.completion.chunk", "created": int(time.time()), "model": ""}
    buffers: set[tuple[Any, ...]] = set()
    async for line in response.aiter_lines():
        if not line.startswith("data:"):
            continue
        data = line[5:].lstrip()
        if data == "[DONE]":
            if restorer:
                for key in list(buffers):
                    tail = restorer.flush(key)
                    if tail:
                        choice_index, field, *extra = key
                        delta: dict[str, Any] = {}
                        if field == "content":
                            delta["content"] = tail
                        else:
                            tool_index = extra[0]
                            delta["tool_calls"] = [{"index": tool_index, "function": {"arguments": tail}}]
                        chunk = dict(shell)
                        chunk["choices"] = [{"index": choice_index, "delta": delta, "finish_reason": None}]
                        yield _sse_json(chunk)
            yield "data: [DONE]\n\n"
            return
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            raise RuntimeError("upstream emitted malformed SSE JSON") from None
        if not isinstance(payload, dict):
            raise RuntimeError("upstream emitted an invalid SSE event")
        shell.update({key: payload[key] for key in ("id", "object", "created", "model") if key in payload})
        choices = payload.get("choices", [])
        if not isinstance(choices, list):
            raise RuntimeError("upstream emitted invalid choices")
        if not choices:
            yield _sse_json(payload)
            continue
        for choice in choices:
            choice_index = choice.get("index", 0)
            delta = dict(choice.get("delta") or {})
            if restorer:
                content = delta.get("content")
                if isinstance(content, str):
                    key = (choice_index, "content")
                    buffers.add(key)
                    safe = restorer.push(key, content)
                    if safe:
                        delta["content"] = safe
                    else:
                        delta.pop("content", None)
                for tool_call in delta.get("tool_calls", []):
                    function = tool_call.get("function") or {}
                    arguments = function.get("arguments")
                    if isinstance(arguments, str):
                        tool_index = tool_call.get("index", 0)
                        key = (choice_index, "arguments", tool_index)
                        buffers.add(key)
                        safe = restorer.push(key, arguments)
                        if safe:
                            function["arguments"] = safe
                        else:
                            function.pop("arguments", None)
            finish_reason = choice.get("finish_reason")
            if restorer and finish_reason is not None:
                for key in [item for item in buffers if item[0] == choice_index]:
                    tail = restorer.flush(key)
                    if tail:
                        if key[1] == "content":
                            delta["content"] = delta.get("content", "") + tail
                        else:
                            tool_index = key[2]
                            target = next((item for item in delta.get("tool_calls", [])
                                           if item.get("index", 0) == tool_index), None)
                            if target is None:
                                target = {"index": tool_index, "function": {}}
                                delta.setdefault("tool_calls", []).append(target)
                            target.setdefault("function", {})["arguments"] = \
                                target.get("function", {}).get("arguments", "") + tail
            # A chunk whose only text was a withheld token prefix must not expose it.
            if not delta and finish_reason is None:
                continue
            chunk = dict(shell)
            chunk["choices"] = [{"index": choice_index, "delta": delta, "finish_reason": finish_reason}]
            if "logprobs" in choice:
                chunk["choices"][0]["logprobs"] = choice["logprobs"]
            yield _sse_json(chunk)
    if restorer:
        for key in list(buffers):
            tail = restorer.flush(key)
            if tail:
                index, field, *extra = key
                delta = {"content": tail} if field == "content" else {
                    "tool_calls": [{"index": extra[0], "function": {"arguments": tail}}]}
                chunk = dict(shell)
                chunk["choices"] = [{"index": index, "delta": delta, "finish_reason": None}]
                yield _sse_json(chunk)
    yield "data: [DONE]\n\n"


async def _stream_anthropic_events(response: httpx.Response, restorer: StreamingPlaceholderRestorer | None):
    """Translate Anthropic text/tool SSE deltas to OpenAI-compatible SSE chunks."""
    shell = {"id": "", "object": "chat.completion.chunk", "created": int(time.time()), "model": ""}
    buffers: set[tuple[Any, ...]] = set()
    tool_indices: dict[int, int] = {}
    next_tool_index = 0

    async def emit(delta: dict[str, Any], finish_reason: str | None = None) -> str:
        payload = dict(shell)
        payload["choices"] = [{"index": 0, "delta": delta, "finish_reason": finish_reason}]
        return _sse_json(payload)

    async for line in response.aiter_lines():
        if not line.startswith("data:"):
            continue
        data = line[5:].lstrip()
        if data == "[DONE]":
            yield "data: [DONE]\n\n"
            return
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            raise RuntimeError("upstream emitted malformed Anthropic SSE JSON") from None
        event_type = event.get("type")
        if event_type == "message_start":
            message = event.get("message", {})
            shell.update({"id": message.get("id", ""), "model": message.get("model", "")})
            yield await emit({"role": "assistant"})
        elif event_type == "content_block_start":
            block = event.get("content_block", {})
            block_index = event.get("index", 0)
            if block.get("type") == "tool_use":
                tool_index = next_tool_index
                next_tool_index += 1
                tool_indices[block_index] = tool_index
                yield await emit({"tool_calls": [{"index": tool_index, "id": block.get("id", ""),
                    "type": "function", "function": {"name": block.get("name", ""), "arguments": ""}}]})
        elif event_type == "content_block_delta":
            block_index = event.get("index", 0)
            delta = event.get("delta", {})
            if delta.get("type") == "text_delta":
                text = delta.get("text", "")
                if restorer:
                    key = (0, "content")
                    buffers.add(key)
                    text = restorer.push(key, text)
                if text:
                    yield await emit({"content": text})
            elif delta.get("type") == "input_json_delta":
                text = delta.get("partial_json", "")
                tool_index = tool_indices.get(block_index, 0)
                if restorer:
                    key = (0, "arguments", tool_index)
                    buffers.add(key)
                    text = restorer.push(key, text)
                if text:
                    yield await emit({"tool_calls": [{"index": tool_index,
                        "function": {"arguments": text}}]})
        elif event_type == "message_delta":
            if restorer:
                for key in list(buffers):
                    tail = restorer.flush(key)
                    if tail:
                        if key[1] == "content":
                            yield await emit({"content": tail})
                        else:
                            yield await emit({"tool_calls": [{"index": key[2],
                                "function": {"arguments": tail}}]})
            finish_reason = {"end_turn": "stop", "stop_sequence": "stop",
                             "max_tokens": "length", "tool_use": "tool_calls"}.get(
                                 event.get("delta", {}).get("stop_reason"), "stop")
            yield await emit({}, finish_reason)
        elif event_type == "message_stop":
            yield "data: [DONE]\n\n"
            return
        elif event_type == "error":
            yield _sse_json({"error": {"type": "upstream_error", "message": "Upstream stream failed"}})
            return
    if restorer:
        for key in list(buffers):
            tail = restorer.flush(key)
            if tail:
                if key[1] == "content":
                    yield await emit({"content": tail})
                else:
                    yield await emit({"tool_calls": [{"index": key[2], "function": {"arguments": tail}}]})
    yield "data: [DONE]\n\n"


def _iter_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)


def _replace_strings(value: Any, replacements: Iterator[str]) -> Any:
    if isinstance(value, str):
        return next(replacements)
    if isinstance(value, list):
        return [_replace_strings(child, replacements) for child in value]
    if isinstance(value, dict):
        return {key: _replace_strings(child, replacements) for key, child in value.items()}
    return value


def _joined_strings(value: Any) -> tuple[str, str, int]:
    strings = list(_iter_strings(value))
    # NUL-only separators remain field boundaries for Presidio and cannot be
    # misclassified as an entity. Lengthen until the delimiter is collision-free.
    delimiter = "\x00" * 32
    while any(delimiter in item for item in strings):
        delimiter += "\x00"
    return delimiter.join(strings), delimiter, len(strings)


def _rewrite_strings(value: Any, rewritten: str, delimiter: str, count: int) -> Any:
    if count == 0:
        return value
    parts = rewritten.split(delimiter)
    if len(parts) != count:
        raise RuntimeError("internal text segmentation mismatch")
    return _replace_strings(value, iter(parts))


def _load_engine_from_environment() -> TokenizationEngine:
    # Optional local development file. Production should inject variables via
    # the deployment secret manager instead.
    try:
        from dotenv import load_dotenv
        env_file = get_setting("AEGIS_ENV_FILE", ".env.redis")
        candidate = Path(env_file)
        if not candidate.is_absolute():
            candidate = Path(__file__).resolve().parent / candidate
        if candidate.is_file():
            load_dotenv(candidate, override=False)
    except ImportError:
        pass

    pii_engine = get_setting("AEGIS_PII_ENGINE", "pattern").strip().lower()
    if pii_engine == "pattern":
        detector = PatternDetector()
    elif pii_engine == "presidio":
        detector = PatternDetector.with_presidio()
    else:
        raise RuntimeError("SUTRAKSH_PII_ENGINE must be 'pattern' or 'presidio' (legacy: AEGIS_PII_ENGINE)")

    aes_key = get_setting("SUTRAKSH_AES_KEY_B64", None, "AEGIS_AES_KEY_B64", "AES_KEY_B64")
    index_key = get_setting("SUTRAKSH_INDEX_KEY_B64", None, "AEGIS_INDEX_KEY_B64", "INDEX_KEY_B64")
    if not aes_key or not index_key:
        raise RuntimeError("proxy encryption keys are not configured")
    root = Path(__file__).resolve().parent
    tls_dir = Path(get_setting("AEGIS_REDIS_TLS_DIR", str(root / "secrets" / "redis-tls")))
    client = create_tls_redis_client(
        host=get_setting("SUTRAKSH_REDIS_HOST", "127.0.0.1", "AEGIS_REDIS_HOST", "REDIS_HOST"),
        port=int(get_setting("SUTRAKSH_REDIS_PORT", "6380", "AEGIS_REDIS_PORT", "REDIS_PORT")),
        username=get_setting("SUTRAKSH_REDIS_USERNAME", "", "AEGIS_REDIS_USERNAME", "REDIS_USERNAME"),
        password=get_setting("SUTRAKSH_REDIS_PASSWORD", "", "AEGIS_REDIS_PASSWORD", "REDIS_PASSWORD"),
        ca_certs=get_setting("SUTRAKSH_REDIS_CA_CERTS", str(tls_dir / "ca.crt"), "AEGIS_REDIS_CA_CERTS"),
        client_cert=get_setting("SUTRAKSH_REDIS_CLIENT_CERT", str(tls_dir / "client.crt"), "AEGIS_REDIS_CLIENT_CERT"),
        client_key=get_setting("SUTRAKSH_REDIS_CLIENT_KEY", str(tls_dir / "client.key"), "AEGIS_REDIS_CLIENT_KEY"),
    )
    vault = RedisTokenVault(
        client, MappingCipher.from_base64(aes_key),
        index_key=base64.b64decode(index_key, validate=True),
        ttl_seconds=int(get_setting("AEGIS_VAULT_TTL_SECONDS", "600")),
    )
    return TokenizationEngine(detector, vault)


def _upstream_url(base_url: str, provider: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("upstream base URL is invalid")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("unencrypted HTTP is permitted only for local upstreams")
    if parsed.query or parsed.fragment:
        raise ValueError("upstream base URL must not contain query or fragment")
    base = base_url.rstrip("/")
    versioned = parsed.path.rstrip("/").endswith("/v1")
    if provider == "anthropic":
        return base + "/messages" if versioned else base + "/v1/messages"
    return base + "/chat/completions" if versioned else base + "/v1/chat/completions"


def _to_anthropic_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate the common OpenAI chat subset into Anthropic Messages format."""
    system_parts: list[str] = []
    messages: list[dict[str, Any]] = []
    for message in payload["messages"]:
        if not isinstance(message, dict):
            raise ValueError("message entries must be objects")
        role = message.get("role")
        content = message.get("content", "")
        if role == "system" or role == "developer":
            if not isinstance(content, str):
                raise ValueError("Anthropic adapter supports text system messages only")
            system_parts.append(content)
        elif role in {"user", "assistant"}:
            if not isinstance(content, (str, list)):
                raise ValueError("Anthropic adapter requires text-compatible message content")
            converted = {"role": role, "content": content}
            if role == "assistant" and message.get("tool_calls"):
                blocks = []
                if content:
                    blocks.append({"type": "text", "text": content})
                for call in message["tool_calls"]:
                    function = call.get("function", {})
                    try:
                        arguments = json.loads(function.get("arguments", "{}"))
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise ValueError("assistant tool-call arguments must be JSON") from exc
                    blocks.append({"type": "tool_use", "id": call.get("id", ""),
                                   "name": function.get("name", ""), "input": arguments})
                converted["content"] = blocks
            messages.append(converted)
        elif role == "tool":
            messages.append({"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": message.get("tool_call_id", ""),
                "content": content if isinstance(content, str) else json.dumps(content),
            }]})
        else:
            raise ValueError("unsupported message role for Anthropic adapter")

    result: dict[str, Any] = {
        "model": payload.get("model"),
        "max_tokens": payload.get("max_tokens", payload.get("max_completion_tokens",
                                                               int(get_setting("SUTRAKSH_ANTHROPIC_DEFAULT_MAX_TOKENS", "1024", "ANTHROPIC_DEFAULT_MAX_TOKENS")))),
        "messages": messages,
    }
    if payload.get("stream") is True:
        result["stream"] = True
    if system_parts:
        result["system"] = "\n\n".join(system_parts)
    for field in ("temperature", "top_p", "top_k", "metadata"):
        if field in payload:
            result[field] = payload[field]
    if "stop" in payload:
        stop = payload["stop"]
        result["stop_sequences"] = stop if isinstance(stop, list) else [stop]
    if "tools" in payload:
        tools = []
        for item in payload["tools"]:
            if item.get("type") != "function":
                raise ValueError("Anthropic adapter supports OpenAI function tools only")
            function = item["function"]
            tools.append({"name": function["name"], "description": function.get("description", ""),
                          "input_schema": function.get("parameters", {"type": "object", "properties": {}})})
        result["tools"] = tools
    choice = payload.get("tool_choice")
    if choice == "auto":
        result["tool_choice"] = {"type": "auto"}
    elif choice == "required":
        result["tool_choice"] = {"type": "any"}
    elif isinstance(choice, dict) and choice.get("type") == "function":
        name = choice.get("function", {}).get("name")
        if name:
            result["tool_choice"] = {"type": "tool", "name": name}
    return result


def _from_anthropic_response(payload: dict[str, Any]) -> dict[str, Any]:
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in payload.get("content", []):
        if block.get("type") == "text":
            text_parts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            tool_calls.append({
                "id": block.get("id", ""), "type": "function",
                "function": {"name": block.get("name", ""),
                             "arguments": json.dumps(block.get("input", {}), separators=(",", ":"))},
            })
    usage = payload.get("usage", {})
    finish_reason = {"end_turn": "stop", "stop_sequence": "stop", "max_tokens": "length",
                     "tool_use": "tool_calls"}.get(payload.get("stop_reason"), "stop")
    message: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts) or None}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": payload.get("id", ""), "object": "chat.completion", "created": 0,
        "model": payload.get("model", ""),
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": usage.get("input_tokens", 0),
                  "completion_tokens": usage.get("output_tokens", 0),
                  "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0)},
    }


def create_app(
    *,
    engine: TokenizationEngine | None = None,
    upstream_client: httpx.AsyncClient | None = None,
    upstream_base_url: str | None = None,
    provider: str | None = None,
    mode: str | None = None,
    tenant_id: str | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        yield
        if application.state.owns_http_client and application.state.http_client is not None:
            await application.state.http_client.aclose()

    app = FastAPI(title="Sutraksh Local LLM Proxy", version="0.1.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.http_client = upstream_client
    app.state.owns_http_client = upstream_client is None
    app.state.http_lock = asyncio.Lock()
    app.state.upstream_base_url = upstream_base_url
    app.state.provider = provider
    app.state.mode = mode
    app.state.tenant_id = tenant_id

    async def client_for_app() -> httpx.AsyncClient:
        if app.state.http_client is not None:
            return app.state.http_client
        async with app.state.http_lock:
            if app.state.http_client is None:
                app.state.http_client = httpx.AsyncClient(timeout=45.0, follow_redirects=False)
        return app.state.http_client

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        raw_body = await request.body()
        if len(raw_body) > _MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="Request is too large")
        try:
            payload = json.loads(raw_body)
        except Exception:
            raise HTTPException(status_code=400, detail="Request body must be valid JSON") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            raise HTTPException(status_code=400, detail="A chat completion messages array is required")
        streaming = payload.get("stream") is True

        base_url = app.state.upstream_base_url or get_setting("AEGIS_UPSTREAM_BASE_URL")
        provider_name = (app.state.provider or get_setting("AEGIS_UPSTREAM_PROVIDER", "openai")).lower()
        active_mode = (app.state.mode or get_setting("AEGIS_MODE", "enforce")).lower()
        if not base_url:
            raise HTTPException(status_code=500, detail="Upstream provider is not configured")
        if provider_name not in {"openai", "anthropic", "ollama"}:
            raise HTTPException(status_code=500, detail="Upstream provider configuration is invalid")
        if active_mode not in {"enforce", "warn"}:
            raise HTTPException(status_code=500, detail="Proxy mode configuration is invalid")
        try:
            target_url = _upstream_url(base_url, provider_name)
        except ValueError:
            raise HTTPException(status_code=500, detail="Upstream base URL configuration is invalid") from None

        upstream_key = request.headers.get("x-upstream-api-key", "").strip()
        if provider_name in {"openai", "anthropic"} and not upstream_key:
            raise HTTPException(status_code=401, detail="X-Upstream-Api-Key is required")
        try:
            if app.state.engine is not None:
                active_engine = app.state.engine
            elif active_mode == "warn":
                active_engine = TokenizationEngine(PatternDetector(), InMemoryTokenVault())
            else:
                active_engine = _load_engine_from_environment()
            app.state.engine = active_engine
        except Exception as exc:
            logger.error("Proxy security engine is unavailable (%s)", type(exc).__name__)
            raise HTTPException(status_code=500, detail="Security processing is unavailable") from None

        request_session = uuid.uuid4().hex
        request_tenant = app.state.tenant_id or get_setting("AEGIS_TENANT_ID", "local-dev")
        safe_payload = payload
        joined_prompt, delimiter, prompt_count = _joined_strings(payload["messages"])
        if active_mode == "enforce" and prompt_count:
            try:
                tokenized = active_engine.tokenize(joined_prompt, request_session, tenant_id=request_tenant)
                safe_payload = dict(payload)
                safe_payload["messages"] = _rewrite_strings(
                    payload["messages"], tokenized.sanitized_text, delimiter, prompt_count)
                if streaming:
                    # Resolve all prompt placeholders before response headers are
                    # sent. The stream restorer then uses this request-local map
                    # and never depends on Redis after the first client byte.
                    active_engine.resolve_tokens(
                        tokenized.sanitized_text, request_session, tenant_id=request_tenant)
            except Exception as exc:
                logger.error("Prompt protection failed; request blocked (%s)", type(exc).__name__)
                raise HTTPException(status_code=500, detail="Request blocked by security processing failure") from None
        elif active_mode == "warn" and prompt_count:
            findings = active_engine.detector.detect(joined_prompt)
            if findings:
                logger.warning("Sensitive patterns detected in warn mode: count=%d kinds=%s",
                               len(findings), sorted({item.kind for item in findings}))

        outbound_headers = {
            "content-type": "application/json",
            "accept": "text/event-stream" if streaming else "application/json",
        }
        if upstream_key:
            if provider_name == "anthropic":
                outbound_headers["x-api-key"] = upstream_key
                outbound_headers["anthropic-version"] = get_setting("SUTRAKSH_ANTHROPIC_VERSION", "2023-06-01", "ANTHROPIC_VERSION")
            else:
                outbound_headers["authorization"] = f"Bearer {upstream_key}"
        try:
            if provider_name == "anthropic":
                safe_payload = _to_anthropic_request(safe_payload)
        except (ValueError, KeyError, TypeError):
            raise HTTPException(status_code=400, detail="Request uses an unsupported Anthropic chat feature") from None

        if streaming:
            upstream_client = await client_for_app()
            stream_context = upstream_client.stream(
                "POST", target_url, json=safe_payload, headers=outbound_headers, follow_redirects=False)
            try:
                upstream = await stream_context.__aenter__()
            except httpx.TimeoutException:
                raise HTTPException(status_code=504, detail="Upstream request timed out") from None
            except httpx.RequestError:
                raise HTTPException(status_code=502, detail="Upstream request failed") from None
            if upstream.status_code >= 400:
                try:
                    error_body = json.loads(await upstream.aread())
                except Exception:
                    error_body = {"error": {"message": "Upstream request failed"}}
                await stream_context.__aexit__(None, None, None)
                if active_mode == "enforce":
                    try:
                        joined_error, error_delimiter, error_count = _joined_strings(error_body)
                        if error_count:
                            restored_error = active_engine.restore(
                                joined_error, request_session, tenant_id=request_tenant)
                            error_body = _rewrite_strings(error_body, restored_error, error_delimiter, error_count)
                    except Exception:
                        raise HTTPException(status_code=500, detail="Response withheld because restoration failed") from None
                return JSONResponse(content=error_body, status_code=upstream.status_code)
            if not upstream.headers.get("content-type", "").lower().startswith("text/event-stream"):
                await upstream.aread()
                await stream_context.__aexit__(None, None, None)
                raise HTTPException(status_code=502, detail="Upstream did not return an SSE stream")

            restorer = StreamingPlaceholderRestorer(
                active_engine, request_session, request_tenant) if active_mode == "enforce" else None

            async def stream_body():
                try:
                    stream_fn = _stream_anthropic_events if provider_name == "anthropic" else _stream_openai_events
                    async for part in stream_fn(upstream, restorer):
                        yield part
                except Exception as exc:
                    logger.error("Stream processing failed; stream terminated (%s)", type(exc).__name__)
                    yield _sse_json({"error": {"type": "aegismcp_security_error",
                                                  "message": "Stream terminated by security proxy"}})
                finally:
                    await stream_context.__aexit__(None, None, None)

            return StreamingResponse(stream_body(), status_code=upstream.status_code,
                                     media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

        try:
            upstream = await (await client_for_app()).post(
                target_url, json=safe_payload, headers=outbound_headers, follow_redirects=False)
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Upstream request timed out") from None
        except httpx.RequestError:
            raise HTTPException(status_code=502, detail="Upstream request failed") from None

        try:
            result = upstream.json()
            if not isinstance(result, (dict, list)):
                raise ValueError("expected JSON object or array")
            if provider_name == "anthropic" and upstream.status_code < 400:
                result = _from_anthropic_response(result)
        except Exception:
            raise HTTPException(status_code=502, detail="Upstream returned an invalid JSON response") from None

        if active_mode == "enforce":
            joined_response, response_delimiter, response_count = _joined_strings(result)
            if response_count:
                try:
                    restored = active_engine.restore(joined_response, request_session, tenant_id=request_tenant)
                    result = _rewrite_strings(result, restored, response_delimiter, response_count)
                except Exception as exc:
                    logger.error("Response restoration failed; response withheld (%s)", type(exc).__name__)
                    raise HTTPException(status_code=500, detail="Response withheld because restoration failed") from None

        return JSONResponse(content=result, status_code=upstream.status_code)

    return app


app = create_app()
