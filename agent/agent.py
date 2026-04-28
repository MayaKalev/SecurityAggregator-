"""LLM tool-use loop using OpenAI's chat completions API.

Reads OPENAI_API_KEY and OPENAI_MODEL from the environment.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from openai import OpenAI

from tools import TOOLS, TOOL_DISPATCH

log = logging.getLogger("agent")

MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
MAX_TOKENS = 8192
MAX_ITERATIONS = 25  # safety stop for the agent loop

openai_client = OpenAI()  # reads OPENAI_API_KEY

# Convert MCP-style schemas into OpenAI's "function" tool shape once at import.
OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["input_schema"],
        },
    }
    for t in TOOLS
]


def run(user_request: str, system_prompt: str) -> str:
    """Run the agent until it stops requesting tool calls. Returns final text.

    `system_prompt` selects the flow: SYSTEM_INSTRUCTIONS_BATCH (items
    pre-provided) or SYSTEM_INSTRUCTIONS_BY_ID (agent fetches by ID).
    """
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_request},
    ]

    for step in range(1, MAX_ITERATIONS + 1):
        log.debug("step %d: calling model…", step)
        resp = openai_client.chat.completions.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            tools=OPENAI_TOOLS,
            messages=messages,
        )

        choice = resp.choices[0]
        msg = choice.message

        # Echo the assistant turn back into the conversation, including any
        # tool_calls — the API requires them on the next turn.
        assistant_turn: dict[str, Any] = {"role": "assistant", "content": msg.content}
        if msg.tool_calls:
            assistant_turn["tool_calls"] = [
                {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function.name,
                        "arguments": tool_call.function.arguments,
                    },
                }
                for tool_call in msg.tool_calls
            ]
        messages.append(assistant_turn)

        if choice.finish_reason != "tool_calls" or not msg.tool_calls:
            log.debug(
                "model stopped (reason=%s) after %d step(s)", choice.finish_reason, step
            )
            return (msg.content or "").strip()

        for tool_call in msg.tool_calls:
            name = tool_call.function.name
            try:
                args = json.loads(tool_call.function.arguments or "{}")
            except json.JSONDecodeError as exc:
                output, is_error = ({"error": f"bad JSON args: {exc}"}, True)
            else:
                output, is_error = _invoke(name, args)

            log.info("tool %-20s %s", name, "ERROR" if is_error else "ok")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(output, default=str),
                }
            )

    raise RuntimeError(f"agent exceeded MAX_ITERATIONS={MAX_ITERATIONS}")


def _invoke(name: str, args: dict) -> tuple[Any, bool]:
    """Look up `name` in TOOL_DISPATCH and call it. Returns (output, is_error).
    """
    fn = TOOL_DISPATCH.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}, True
    try:
        result = fn(**args)
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}"}, True
    except Exception as exc:
        return {"error": str(exc), "type": type(exc).__name__}, True
    is_error = isinstance(result, dict) and result.get("ok") is False
    return result, is_error
