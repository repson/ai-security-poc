"""
Tools available to the agent.
Each tool is defined as a Python function plus its JSON schema descriptor
so it can be passed directly to the OpenAI function-calling API.
"""

import json
import math
import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def get_current_datetime() -> dict:
    """Return the current date and time (UTC)."""
    now = datetime.datetime.utcnow()
    return {
        "utc": now.isoformat() + "Z",
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "weekday": now.strftime("%A"),
    }


def calculator(expression: str) -> dict:
    """
    Evaluate a safe mathematical expression and return the result.

    Only basic arithmetic and common math functions are allowed.
    """
    allowed_names = {k: v for k, v in math.__dict__.items() if not k.startswith("_")}
    allowed_names.update({"abs": abs, "round": round})

    try:
        # Compile first to catch syntax errors before eval
        code = compile(expression, "<string>", "eval")
        # Check that no names outside the allowed set are used
        for name in code.co_names:
            if name not in allowed_names:
                return {"error": f"Name '{name}' is not allowed in expressions."}
        result = eval(code, {"__builtins__": {}}, allowed_names)  # noqa: S307
        return {"expression": expression, "result": result}
    except Exception as exc:
        return {"error": str(exc)}


def web_search(query: str) -> dict:
    """
    Simulate a web search.  In this PoC the results are mocked so that no
    external API key is needed.  Replace the body with a real search client
    (e.g. Tavily, SerpAPI, DuckDuckGo) when integrating NeMo Guardrails.
    """
    mock_results = [
        {
            "title": f"Result 1 for '{query}'",
            "url": "https://example.com/1",
            "snippet": (
                f"This is a simulated search result for the query '{query}'. "
                "In a real deployment this would contain actual web content."
            ),
        },
        {
            "title": f"Result 2 for '{query}'",
            "url": "https://example.com/2",
            "snippet": (
                f"Another simulated result for '{query}'. "
                "Replace this function with a real search API for production use."
            ),
        },
    ]
    return {"query": query, "results": mock_results}


# ---------------------------------------------------------------------------
# OpenAI tool schemas
# ---------------------------------------------------------------------------

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_current_datetime",
            "description": "Returns the current UTC date and time.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculator",
            "description": (
                "Evaluates a mathematical expression using standard arithmetic "
                "and functions from Python's math module (sin, cos, sqrt, log, etc.)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "A valid Python math expression, e.g. '2 ** 10' or 'sqrt(144)'.",
                    }
                },
                "required": ["expression"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Searches the web for the given query and returns a list of results "
                "with titles, URLs and snippets. Currently returns mock data."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query string.",
                    }
                },
                "required": ["query"],
            },
        },
    },
]

# ---------------------------------------------------------------------------
# Dispatcher: maps tool name → function
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, Any] = {
    "get_current_datetime": get_current_datetime,
    "calculator": calculator,
    "web_search": web_search,
}


def dispatch_tool(name: str, arguments_json: str) -> str:
    """Call the tool identified by *name* with the given JSON arguments."""
    if name not in TOOL_REGISTRY:
        return json.dumps({"error": f"Unknown tool: {name}"})

    try:
        args: dict = json.loads(arguments_json) if arguments_json else {}
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid JSON arguments: {exc}"})

    result = TOOL_REGISTRY[name](**args)
    return json.dumps(result, ensure_ascii=False)
