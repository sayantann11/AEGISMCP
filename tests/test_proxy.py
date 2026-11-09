import json
import base64
import os
from pathlib import Path
import uuid

import httpx
import pytest

from aegismcp.detectors import PatternDetector
from aegismcp.engine import TokenizationEngine
from aegismcp.crypto import MappingCipher
from aegismcp.redis_vault import RedisTokenVault, create_tls_redis_client
from aegismcp.vault import InMemoryTokenVault, VaultError
from proxy_server import StreamingPlaceholderRestorer, create_app


FAKE_SECRET = "sk-test-123456789012345678901234"


class ChunkedSSE(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        return None


def sse_event(payload: dict) -> bytes:
    return ("data: " + json.dumps(payload, separators=(",", ":")) + "\n\n").encode()


def live_redis_engine() -> TokenizationEngine:
    root = Path(__file__).resolve().parents[1]
    config = {}
    for line in (root / ".env.redis").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()
    for key in ("REDIS_HOST", "REDIS_PORT", "REDIS_USERNAME", "REDIS_PASSWORD"):
        if os.getenv(key):
            config[key] = os.environ[key]
    tls = root / "secrets" / "redis-tls"
    client = create_tls_redis_client(host=config["REDIS_HOST"], port=int(config["REDIS_PORT"]),
        username=config["REDIS_USERNAME"], password=config["REDIS_PASSWORD"],
        ca_certs=str(tls / "ca.crt"), client_cert=str(tls / "client.crt"), client_key=str(tls / "client.key"))
    vault = RedisTokenVault(client, MappingCipher.from_base64(config["AES_KEY_B64"]),
        index_key=base64.b64decode(config["INDEX_KEY_B64"], validate=True), ttl_seconds=300)
    return TokenizationEngine(PatternDetector(), vault)


@pytest.mark.asyncio
async def test_proxy_sanitizes_upstream_and_restores_response():
    upstream_requests = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        upstream_requests.append((request, body))
        user_text = body["messages"][1]["content"]
        assert FAKE_SECRET not in user_text
        assert "[API_KEY_01]" in user_text
        return httpx.Response(200, json={
            "id": "chatcmpl-test",
            "choices": [{"message": {"role": "assistant", "content": "I used [API_KEY_01] safely."}}],
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    engine = TokenizationEngine(PatternDetector(), InMemoryTokenVault())
    app = create_app(engine=engine, upstream_client=client,
                     upstream_base_url="https://llm.example/v1", provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post(
            "/v1/chat/completions",
            headers={"X-Upstream-Api-Key": "fake-upstream-key", "Authorization": "Bearer client-key"},
            json={"model": "test-model", "messages": [
                {"role": "system", "content": "Protect API keys."},
                {"role": "user", "content": f"Use this API key: {FAKE_SECRET}"},
            ]},
        )
    await client.aclose()

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == f"I used {FAKE_SECRET} safely."
    sent_request, _ = upstream_requests[0]
    assert sent_request.headers["authorization"] == "Bearer fake-upstream-key"
    assert "x-upstream-api-key" not in sent_request.headers
    assert sent_request.headers["authorization"] != "Bearer client-key"


@pytest.mark.asyncio
async def test_proxy_sanitizes_with_optional_local_presidio():
    pytest.importorskip("presidio_analyzer")
    import spacy
    if not spacy.util.is_package("en_core_web_sm"):
        pytest.skip("install the optional en_core_web_sm model to exercise local NER")
    detector = PatternDetector.with_presidio()

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        prompt = body["messages"][0]["content"]
        assert "John Smith" not in prompt
        assert "London" not in prompt
        assert "[PERSON_01]" in prompt
        assert "[LOCATION_01]" in prompt
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "Sent to [PERSON_01] in [LOCATION_01]."}}],
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    engine = TokenizationEngine(detector, InMemoryTokenVault())
    app = create_app(engine=engine, upstream_client=client,
                     upstream_base_url="https://llm.example/v1", provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post(
            "/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-upstream-key"},
            json={"messages": [{"role": "user", "content":
                                 "Send synthetic report to John Smith in London."}]},
        )
    await client.aclose()

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Sent to John Smith in London."


@pytest.mark.asyncio
async def test_warn_mode_logs_types_but_forwards_original_prompt(caplog):
    seen = {}

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Not modified"}}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    engine = TokenizationEngine(PatternDetector(), InMemoryTokenVault())
    app = create_app(engine=engine, upstream_client=client,
                     upstream_base_url="https://llm.example/v1", provider="openai", mode="warn")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}]})
    await client.aclose()

    assert response.status_code == 200
    assert seen["body"]["messages"][0]["content"] == FAKE_SECRET
    assert FAKE_SECRET not in caplog.text
    assert "API_KEY" in caplog.text


@pytest.mark.asyncio
async def test_vault_error_blocks_before_upstream_call():
    class FailingVault:
        def put(self, *_args, **_kwargs):
            raise VaultError("unavailable")

        def get(self, *_args, **_kwargs):
            raise VaultError("unavailable")

    calls = 0

    def upstream_handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    engine = TokenizationEngine(PatternDetector(), FailingVault())
    app = create_app(engine=engine, upstream_client=client,
                     upstream_base_url="https://llm.example/v1", provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}]})
    await client.aclose()

    assert response.status_code == 500
    assert calls == 0
    assert FAKE_SECRET not in response.text


@pytest.mark.asyncio
async def test_streaming_sanitizes_and_restores_split_placeholder_across_sse_events():
    captured = {}
    events = [
        {"id": "stream-1", "object": "chat.completion.chunk", "created": 1, "model": "test",
         "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]},
        {"id": "stream-1", "object": "chat.completion.chunk", "created": 1, "model": "test",
         "choices": [{"index": 0, "delta": {"content": f"Echo [API_KEY_"}, "finish_reason": None}]},
        {"id": "stream-1", "object": "chat.completion.chunk", "created": 1, "model": "test",
         "choices": [{"index": 0, "delta": {"content": "01] complete"}, "finish_reason": None}]},
        {"id": "stream-1", "object": "chat.completion.chunk", "created": 1, "model": "test",
         "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ]
    chunks = [sse_event(item) for item in events] + [b"data: [DONE]\n\n"]
    # Also split transport bytes inside an SSE line, independently of the
    # placeholder split across two semantic completion events.
    wire = b"".join(chunks)
    stream = ChunkedSSE([wire[:17], wire[17:83], wire[83:211], wire[211:]])

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        captured["headers"] = request.headers
        assert FAKE_SECRET not in json.dumps(captured["body"])
        assert "[API_KEY_01]" in captured["body"]["messages"][0]["content"]
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(engine=TokenizationEngine(PatternDetector(), InMemoryTokenVault()),
                     upstream_client=client, upstream_base_url="https://llm.example/v1",
                     provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "[API_KEY_" not in response.text
    text_parts = []
    for frame in response.text.split("\n\n"):
        if frame.startswith("data: {"):
            event = json.loads(frame[6:])
            for choice in event.get("choices", []):
                text_parts.append(choice.get("delta", {}).get("content", ""))
    assert "".join(text_parts) == f"Echo {FAKE_SECRET} complete"
    assert "data: [DONE]" in response.text
    assert captured["body"]["stream"] is True


@pytest.mark.asyncio
async def test_streaming_vault_failure_blocks_before_upstream_call():
    class FailingVault:
        def put(self, *_args, **_kwargs):
            raise VaultError("unavailable")

        def get(self, *_args, **_kwargs):
            raise VaultError("unavailable")

    calls = 0
    def upstream_handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=ChunkedSSE([]))

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    engine = TokenizationEngine(PatternDetector(), FailingVault())
    app = create_app(engine=engine, upstream_client=client, upstream_base_url="https://llm.example/v1",
                     provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()
    assert response.status_code == 500
    assert calls == 0
    assert FAKE_SECRET not in response.text


@pytest.mark.asyncio
async def test_encryption_failure_blocks_upstream_before_stream_starts():
    class FailingCipher:
        def encrypt(self, *_args, **_kwargs):
            raise RuntimeError("encryption unavailable")

        def decrypt(self, *_args, **_kwargs):
            raise RuntimeError("decryption unavailable")

    class FakeRedis:
        def __init__(self):
            self.writes = 0
        def set(self, *_args, **_kwargs):
            self.writes += 1
            return True

    redis_client = FakeRedis()
    vault = RedisTokenVault(redis_client, FailingCipher(), index_key=b"i" * 32, ttl_seconds=300)
    engine = TokenizationEngine(PatternDetector(), vault)
    upstream_calls = 0
    def upstream_handler(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=ChunkedSSE([]))

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(engine=engine, upstream_client=client, upstream_base_url="https://llm.example/v1",
                     provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()

    assert response.status_code == 500
    assert redis_client.writes == 0
    assert upstream_calls == 0


@pytest.mark.asyncio
async def test_vault_lookup_failure_blocks_stream_before_upstream_starts():
    class ReadFailVault:
        def put(self, *_args, **_kwargs):
            return None
        def get(self, *_args, **_kwargs):
            raise VaultError("redis read unavailable")

    calls = 0
    def upstream_handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=ChunkedSSE([]))

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(engine=TokenizationEngine(PatternDetector(), ReadFailVault()),
                     upstream_client=client, upstream_base_url="https://llm.example/v1",
                     provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()
    assert response.status_code == 500
    assert calls == 0
    assert FAKE_SECRET not in response.text


@pytest.mark.asyncio
async def test_streaming_unknown_placeholder_is_withheld():
    event = {"id": "stream-2", "object": "chat.completion.chunk", "created": 1, "model": "test",
             "choices": [{"index": 0, "delta": {"content": "[API_KEY_99]"}, "finish_reason": None}]}
    def upstream_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              stream=ChunkedSSE([sse_event(event), b"data: [DONE]\n\n"]))

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(engine=TokenizationEngine(PatternDetector(), InMemoryTokenVault()),
                     upstream_client=client, upstream_base_url="https://llm.example/v1",
                     provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()
    assert response.status_code == 200
    assert "[API_KEY_99]" not in response.text
    assert "aegismcp_security_error" in response.text


@pytest.mark.asyncio
async def test_anthropic_messages_adapter_uses_provider_auth_and_openai_response_shape():
    captured = {}

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.content)
        assert FAKE_SECRET not in json.dumps(captured["body"])
        assert "[API_KEY_01]" in captured["body"]["messages"][0]["content"]
        return httpx.Response(200, json={
            "id": "msg-test", "type": "message", "role": "assistant", "model": "claude-test",
            "content": [{"type": "text", "text": "Protected [API_KEY_01]"}],
            "stop_reason": "end_turn", "usage": {"input_tokens": 4, "output_tokens": 3},
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    engine = TokenizationEngine(PatternDetector(), InMemoryTokenVault())
    app = create_app(engine=engine, upstream_client=client,
                     upstream_base_url="https://api.anthropic.com/v1", provider="anthropic", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-anthropic-key"},
                                    json={"model": "claude-test", "max_tokens": 50,
                                          "messages": [{"role": "user", "content": FAKE_SECRET}]})
    await client.aclose()

    assert response.status_code == 200
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "fake-anthropic-key"
    assert "x-upstream-api-key" not in captured["headers"]
    assert captured["body"]["max_tokens"] == 50
    assert response.json()["choices"][0]["message"]["content"] == f"Protected {FAKE_SECRET}"


@pytest.mark.asyncio
async def test_anthropic_stream_is_translated_and_restored_across_delta_boundary():
    events = [
        {"type": "message_start", "message": {"id": "msg-stream", "model": "claude-test"}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": "Value: [API_KEY_"}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": "01]"}},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}},
        {"type": "message_stop"},
    ]
    wire = b"".join(b"event: " + event["type"].encode() + b"\n" + sse_event(event) for event in events)
    captured = {}

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        assert FAKE_SECRET not in json.dumps(captured["body"])
        assert captured["body"]["stream"] is True
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              stream=ChunkedSSE([wire[:71], wire[71:209], wire[209:]]))

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(engine=TokenizationEngine(PatternDetector(), InMemoryTokenVault()),
                     upstream_client=client, upstream_base_url="https://api.anthropic.com/v1",
                     provider="anthropic", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-anthropic-key"},
                                    json={"model": "claude-test", "messages": [
                                        {"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()

    assert response.status_code == 200
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert "[API_KEY_" not in response.text
    assert FAKE_SECRET in response.text
    assert '"finish_reason":"stop"' in response.text
    assert "data: [DONE]" in response.text


@pytest.mark.asyncio
async def test_streaming_tool_arguments_restore_placeholder_split_across_chunks():
    chunks = [
        {"id": "tool-stream", "object": "chat.completion.chunk", "created": 2, "model": "test",
         "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call-1", "type": "function",
             "function": {"name": "lookup", "arguments": '{"key":"[API_KEY_'}}]}, "finish_reason": None}]},
        {"id": "tool-stream", "object": "chat.completion.chunk", "created": 2, "model": "test",
         "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0,
             "function": {"arguments": '01]"}'}}]}, "finish_reason": None}]},
        {"id": "tool-stream", "object": "chat.completion.chunk", "created": 2, "model": "test",
         "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
    ]
    def upstream_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              stream=ChunkedSSE([b"".join(sse_event(item) for item in chunks) + b"data: [DONE]\n\n"]))

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(engine=TokenizationEngine(PatternDetector(), InMemoryTokenVault()),
                     upstream_client=client, upstream_base_url="https://llm.example/v1",
                     provider="openai", mode="enforce")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()

    arguments = []
    for frame in response.text.split("\n\n"):
        if frame.startswith("data: {"):
            payload = json.loads(frame[6:])
            for choice in payload.get("choices", []):
                for tool in choice.get("delta", {}).get("tool_calls", []):
                    arguments.append(tool.get("function", {}).get("arguments", ""))
    assert "[API_KEY_" not in response.text
    assert json.loads("".join(arguments)) == {"key": FAKE_SECRET}


@pytest.mark.asyncio
@pytest.mark.skipif(os.getenv("SUTRAKSH_LIVE_REDIS", os.getenv("AEGIS_LIVE_REDIS")) != "1",
                    reason="requires the live Redis Compose test environment")
async def test_proxy_stream_restores_using_live_tls_redis():
    events = [
        {"id": "live-stream", "object": "chat.completion.chunk", "created": 2, "model": "test",
         "choices": [{"index": 0, "delta": {"content": "Secret [API_KEY_"}, "finish_reason": None}]},
        {"id": "live-stream", "object": "chat.completion.chunk", "created": 2, "model": "test",
         "choices": [{"index": 0, "delta": {"content": "01]"}, "finish_reason": None}]},
    ]
    def upstream_handler(request: httpx.Request) -> httpx.Response:
        assert FAKE_SECRET not in request.content.decode()
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              stream=ChunkedSSE([b"".join(sse_event(item) for item in events) + b"data: [DONE]\n\n"]))

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream_handler))
    app = create_app(engine=live_redis_engine(), upstream_client=client,
                     upstream_base_url="https://llm.example/v1", provider="openai", mode="enforce",
                     tenant_id="proxy-live-" + uuid.uuid4().hex)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy.test") as proxy:
        response = await proxy.post("/v1/chat/completions", headers={"X-Upstream-Api-Key": "fake-key"},
                                    json={"messages": [{"role": "user", "content": FAKE_SECRET}], "stream": True})
    await client.aclose()
    assert response.status_code == 200
    assert "[API_KEY_" not in response.text
    assert FAKE_SECRET in response.text


def test_stream_buffer_restores_new_dynamic_entity_placeholder():
    engine = TokenizationEngine(PatternDetector(), InMemoryTokenVault())
    engine.tokenize("Card 4111 1111 1111 1111", "stream-card-session")
    restorer = StreamingPlaceholderRestorer(engine, "stream-card-session", "default")
    key = (0, "content")
    assert restorer.push(key, "Card [CREDIT_CARD_") == "Card "
    assert restorer.push(key, "01] used") == "4111 1111 1111 1111 used"
