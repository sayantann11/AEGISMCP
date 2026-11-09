"""Exercise the local proxy against an in-process mock OpenAI-style upstream.

Run the proxy in another terminal, configured with
``--upstream-base-url http://127.0.0.1:8101/v1``. This example never calls a
real LLM provider and uses only a fake secret.
"""

from __future__ import annotations

import threading
import time

from fastapi import FastAPI, Request
import httpx
import uvicorn


PROXY_URL = "http://127.0.0.1:8000/v1/chat/completions"
MOCK_HOST = "127.0.0.1"
MOCK_PORT = 8101
FAKE_SECRET = "sk-fake-test-key-123456789012345"

mock_app = FastAPI(title="Sutraksh example mock upstream")


@mock_app.post("/v1/chat/completions")
async def mock_chat_completions(request: Request) -> dict:
    payload = await request.json()
    messages = payload.get("messages", [])
    prompt = "\n".join(str(message.get("content", "")) for message in messages)
    print("\n--- Sanitized prompt received by mock upstream ---", flush=True)
    print(prompt, flush=True)
    return {
        "id": "chatcmpl-sutraksh-example",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": f"Mock LLM received: {prompt}"},
            "finish_reason": "stop",
        }],
    }


def main() -> None:
    server = uvicorn.Server(uvicorn.Config(mock_app, host=MOCK_HOST, port=MOCK_PORT,
                                           log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, name="sutraksh-mock-upstream", daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("Mock upstream did not start on 127.0.0.1:8101")

    try:
        response = httpx.post(
            PROXY_URL,
            headers={"X-Upstream-Api-Key": "fake-demo-upstream-key"},
            json={"model": "mock-model", "messages": [
                {"role": "user", "content": f"Please inspect this fake key: {FAKE_SECRET}"},
            ]},
            timeout=20,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        print("\n--- Restored response returned by Sutraksh ---")
        print(content)
        if FAKE_SECRET not in content:
            raise RuntimeError("Expected fake secret was not restored; check proxy/vault configuration")
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
