"""
ASI02 — Tool Misuse & Exploitation
Mitigated agent — Pydantic argument validation on every tool call.

Run:
    python -m src.agents.asi02_tool_misuse.mitigated.agent
"""

from __future__ import annotations

import json, os, sys, textwrap
from dotenv import load_dotenv
from openai import OpenAI
from .validators import ReadFileArgs, FetchUrlArgs, SendEmailArgs

load_dotenv()
if not os.environ.get("OPENAI_API_KEY"):
    print("[Error] OPENAI_API_KEY is not set.")
    sys.exit(1)

MODEL = "gpt-4o-mini"
client = OpenAI()

_FILE_STORE = {"reports/q4.txt": "Q4 revenue: $24.7M."}
_EMAIL_LOG: list = []
_FETCH_LOG: list = []


def read_file(path: str) -> str:
    args = ReadFileArgs(path=path)  # raises on traversal
    return _FILE_STORE.get(args.path, f"[not found: {args.path}]")


def fetch_url(url: str) -> str:
    args = FetchUrlArgs(url=url)  # raises on SSRF
    _FETCH_LOG.append(args.url)
    return f"[mock fetch] {args.url}: HTTP 200 OK"


def send_email(to: str, subject: str, body: str) -> str:
    args = SendEmailArgs(to=to, subject=subject, body=body)  # raises on bad domain
    _EMAIL_LOG.append({"to": args.to, "subject": args.subject})
    return f"Email queued for {args.to}"


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from reports/.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch a public HTTPS URL.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send email to @company.com.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
]
TOOL_MAP = {"read_file": read_file, "fetch_url": fetch_url, "send_email": send_email}


def run(user_message: str) -> str:
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_message},
    ]
    for _ in range(8):
        resp = client.chat.completions.create(
            model=MODEL, messages=messages, tools=TOOLS, tool_choice="auto"
        )
        msg = resp.choices[0].message
        messages.append(msg)
        if resp.choices[0].finish_reason == "stop":
            return msg.content or ""
        for tc in msg.tool_calls or []:
            args = json.loads(tc.function.arguments or "{}")
            try:
                result = TOOL_MAP[tc.function.name](**args)
            except (ValueError, KeyError) as exc:
                result = f"[BLOCKED] {exc}"
                print(f"  [BLOCKED] {tc.function.name}({args}): {exc}")
            else:
                print(f"  [TOOL] {tc.function.name}({args}) → {str(result)[:80]}")
            messages.append(
                {"role": "tool", "tool_call_id": tc.id, "content": str(result)}
            )
    return "[max rounds]"


BANNER = textwrap.dedent("""\
    ┌─────────────────────────────────────────────────────────┐
    │  ASI02 — Tool Misuse  │  MITIGATED                      │
    │  Pydantic validation on all tool arguments              │
    │  Commands: /state  /quit                                │
    └─────────────────────────────────────────────────────────┘
""")


def main() -> None:
    print(BANNER)
    while True:
        try:
            inp = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not inp:
            continue
        if inp.lower() in ("/quit", "/exit"):
            break
        if inp.lower() == "/state":
            print(f"  emails={_EMAIL_LOG}\n  fetched={_FETCH_LOG}\n")
            continue
        print()
        print(f"Agent: {run(inp)}\n")


if __name__ == "__main__":
    main()
