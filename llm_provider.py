"""
llm_provider.py — Thin, swappable adapter over multiple LLM providers.

Supported providers (set LLM_PROVIDER in .env):
  - "gemini"     : Google Gemini API (free tier), raw REST via `requests`.
  - "openrouter" : OpenRouter.ai — many models, several tagged ":free".
  - "grok"       : xAI Grok API (OpenAI-compatible).

Everything is exposed through one function: `chat(messages)` which returns:

    {
        "text": str | None,
        "tool_calls": [{"id": str, "name": str, "arguments": dict}],
        "raw": <provider-specific data to store on the assistant message, or None>,
    }

v2 fixes over the original adapter:
  * Gemini rejects `type: object` schemas without properties and properties
    without a type — schemas are sanitized (such params become JSON strings,
    and agent.py turns them back into objects before the tool runs).
  * Several tool results from one model turn are sent to Gemini as ONE
    message (Gemini requires the counts to match).
  * Gemini "thought signatures" are preserved by echoing the model's raw parts.
  * OpenAI-compatible providers get proper `tool_calls` / `tool_call_id`
    message shapes with string content (the old code sent raw dicts).
  * The Gemini API key travels in a header, so it can never leak into an
    error message that contains the request URL.
  * 429 / 5xx responses are retried with backoff (free tiers rate-limit a lot).
"""

import json
import time

import requests

import config

_OPENAI_COMPATIBLE_ENDPOINTS = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "grok": "https://api.x.ai/v1/chat/completions",
}


def _tool_definitions() -> list:
    import tools
    return tools.TOOL_DEFINITIONS


# ---------------------------------------------------------------------------
# Shared HTTP with retry
# ---------------------------------------------------------------------------

def _post_with_retry(provider: str, url: str, *, headers: dict, payload: dict) -> requests.Response:
    delay = 2.0
    attempts = config.LLM_MAX_RETRIES + 1
    for attempt in range(1, attempts + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=90)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if attempt < attempts:
                print(f"[{provider}: network problem, retrying in {delay:.0f}s ...]")
                time.sleep(delay)
                delay *= 2
                continue
            raise RuntimeError(f"LLM request to {provider} failed: {e}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"LLM request to {provider} failed: {e}")

        if resp.status_code in (429, 500, 502, 503, 504) and attempt < attempts:
            try:
                wait = float(resp.headers.get("Retry-After", delay))
            except ValueError:
                wait = delay
            wait = min(max(wait, 1.0), 30.0)
            print(f"[{provider}: HTTP {resp.status_code} (busy / rate limited), retrying in {wait:.0f}s ...]")
            time.sleep(wait)
            delay *= 2
            continue

        if resp.status_code >= 400:
            hint = ""
            if resp.status_code == 429:
                hint = " (free-tier rate limit — wait a minute or pick another MODEL/provider)"
            elif resp.status_code in (401, 403):
                hint = " (check your API key in .env)"
            elif resp.status_code == 404 and provider == "openrouter":
                hint = " (this model may not support tool calling — pick another :free model that does)"
            raise RuntimeError(f"LLM request to {provider} failed: HTTP {resp.status_code}{hint} {resp.text[:500]}")
        return resp
    raise RuntimeError(f"LLM request to {provider} failed after retries.")


# ---------------------------------------------------------------------------
# OpenAI-compatible providers (OpenRouter, Grok)
# ---------------------------------------------------------------------------

def _openai_tools_schema() -> list:
    return [{"type": "function",
             "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}}
            for t in _tool_definitions()]


def _to_openai_messages(messages: list) -> list:
    out = []
    for m in messages:
        role = m["role"]
        if role in ("system", "user"):
            out.append({"role": role, "content": m["content"]})
        elif role == "assistant":
            entry = {"role": "assistant", "content": m.get("content") or None}
            calls = m.get("tool_calls") or []
            if calls:
                entry["tool_calls"] = [{
                    "id": tc["id"], "type": "function",
                    "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"], default=str)},
                } for tc in calls]
            elif entry["content"] is None:
                entry["content"] = ""
            out.append(entry)
        elif role == "tool":
            out.append({"role": "tool", "tool_call_id": m.get("tool_call_id", ""),
                        "content": json.dumps(m["content"], default=str)})
    return out


def _chat_openai_compatible(provider: str, messages: list) -> dict:
    endpoint = _OPENAI_COMPATIBLE_ENDPOINTS[provider]
    api_key = config.OPENROUTER_API_KEY if provider == "openrouter" else config.GROK_API_KEY
    if not api_key:
        raise RuntimeError(
            f"Missing API key for provider '{provider}'. Set "
            f"{'OPENROUTER_API_KEY' if provider == 'openrouter' else 'GROK_API_KEY'} in .env."
        )

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if provider == "openrouter":
        headers["HTTP-Referer"] = "https://localhost"
        headers["X-Title"] = "controlled-web-agent"

    payload = {
        "model": config.MODEL,
        "messages": _to_openai_messages(messages),
        "tools": _openai_tools_schema(),
        "tool_choice": "auto",
    }
    resp = _post_with_retry(provider, endpoint, headers=headers, payload=payload)

    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError(f"{provider} returned a non-JSON response.")
    if data.get("error"):
        raise RuntimeError(f"{provider} error: {str(data['error'])[:500]}")
    if not data.get("choices"):
        raise RuntimeError(f"{provider} returned no choices.")

    choice = data["choices"][0]["message"]
    tool_calls = []
    for i, tc in enumerate(choice.get("tool_calls") or []):
        try:
            args = json.loads(tc["function"].get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {}
        if not isinstance(args, dict):
            args = {}
        tool_calls.append({"id": tc.get("id") or f"call-{i}", "name": tc["function"]["name"], "arguments": args})
    return {"text": choice.get("content"), "tool_calls": tool_calls, "raw": None}


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

def _gemini_schema(schema: dict) -> dict:
    """Reduce a JSON-schema fragment to what Gemini accepts."""
    if not isinstance(schema, dict):
        return {"type": "string"}
    stype = schema.get("type")
    desc = schema.get("description", "")

    if stype == "object":
        props = schema.get("properties") or {}
        if not props:  # Gemini: "properties should be non-empty for OBJECT type"
            return {"type": "string", "description": (desc + " (Provide as a JSON-encoded string.)").strip()}
        out = {"type": "object", "properties": {k: _gemini_schema(v) for k, v in props.items()}}
        req = [r for r in schema.get("required", []) if r in props]
        if req:
            out["required"] = req
    elif stype == "array":
        out = {"type": "array", "items": _gemini_schema(schema.get("items") or {"type": "string"})}
    elif stype in ("string", "integer", "number", "boolean"):
        out = {"type": stype}
        if stype == "string" and schema.get("enum"):
            out["enum"] = [str(e) for e in schema["enum"]]
    else:  # no type given (e.g. "any JSON value")
        out = {"type": "string"}
        desc = (desc + " (Provide as a JSON-encoded string.)").strip()

    if desc:
        out["description"] = desc
    return out


def _gemini_tools_schema() -> list:
    declarations = []
    for t in _tool_definitions():
        decl = {"name": t["name"], "description": t["description"]}
        params = _gemini_schema(t["parameters"])
        if params.get("properties"):  # functions with no parameters must omit the field
            decl["parameters"] = params
        declarations.append(decl)
    return [{"function_declarations": declarations}]


def _messages_to_gemini_contents(messages: list) -> tuple:
    system_instruction = None
    contents = []
    last_was_tool = False

    for msg in messages:
        role = msg["role"]

        if role == "system":
            system_instruction = msg["content"]
            continue

        if role == "tool":
            part = {"functionResponse": {"name": msg["name"], "response": {"result": msg["content"]}}}
            if last_was_tool and contents:
                contents[-1]["parts"].append(part)  # all results of one turn go in ONE message
            else:
                contents.append({"role": "user", "parts": [part]})
            last_was_tool = True
            continue

        last_was_tool = False
        if role == "user":
            contents.append({"role": "user", "parts": [{"text": msg["content"]}]})
        elif role == "assistant":
            parts = msg.get("provider_raw")  # echo the model's own parts (keeps thought signatures)
            if not parts:
                parts = []
                if msg.get("content"):
                    parts.append({"text": msg["content"]})
                for tc in msg.get("tool_calls", []):
                    parts.append({"functionCall": {"name": tc["name"], "args": tc["arguments"]}})
            if parts:
                contents.append({"role": "model", "parts": parts})

    return system_instruction, contents


def _chat_gemini(messages: list) -> dict:
    if not config.GEMINI_API_KEY:
        raise RuntimeError("Missing GEMINI_API_KEY in .env.")

    system_instruction, contents = _messages_to_gemini_contents(messages)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.MODEL}:generateContent"
    headers = {"Content-Type": "application/json", "x-goog-api-key": config.GEMINI_API_KEY}

    payload = {"contents": contents, "tools": _gemini_tools_schema()}
    if system_instruction:
        payload["system_instruction"] = {"parts": [{"text": system_instruction}]}

    resp = _post_with_retry("gemini", url, headers=headers, payload=payload)
    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError("gemini returned a non-JSON response.")

    if not data.get("candidates"):
        block_reason = (data.get("promptFeedback") or {}).get("blockReason", "unknown")
        raise RuntimeError(f"Gemini returned no candidates (reason: {block_reason}).")

    candidate = data["candidates"][0]
    parts = (candidate.get("content") or {}).get("parts") or []
    if not parts:
        raise RuntimeError(
            f"Gemini returned an empty response (finishReason={candidate.get('finishReason', 'unknown')}). "
            "Try rephrasing the task, or use a different MODEL."
        )

    text_parts, tool_calls = [], []
    for i, part in enumerate(parts):
        if part.get("thought"):
            continue
        if "text" in part:
            text_parts.append(part["text"])
        elif "functionCall" in part:
            fc = part["functionCall"]
            tool_calls.append({"id": f"gemini-call-{i}", "name": fc["name"], "arguments": fc.get("args") or {}})

    return {"text": "\n".join(text_parts) if text_parts else None, "tool_calls": tool_calls, "raw": parts}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def chat(messages: list) -> dict:
    provider = config.LLM_PROVIDER
    if provider == "gemini":
        return _chat_gemini(messages)
    if provider in ("openrouter", "grok"):
        return _chat_openai_compatible(provider, messages)
    raise RuntimeError(f"Unknown LLM_PROVIDER '{provider}'. Use 'gemini', 'openrouter', or 'grok'.")
