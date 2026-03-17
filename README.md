# NeMo Guardrails PoC

Proof-of-concept repository for protecting an agentic application with [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails).

The project is split into two phases:

1. **Base agent** (current) — a minimal but fully functional conversational agent built with the OpenAI SDK.
2. **Guardrails integration** (next) — NeMo Guardrails will be wired in as a middleware layer on top of the base agent.

---

## Project structure

```
nemo-guardrails-poc/
├── src/
│   └── agent/
│       ├── __init__.py   # Package exports (Agent, dispatch_tool, …)
│       ├── agent.py      # Agent class — OpenAI tool-calling loop
│       ├── tools.py      # Tool implementations + OpenAI schemas
│       └── main.py       # Interactive CLI / REPL
├── .env.example          # Environment variable template
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.11+
- An [OpenAI API key](https://platform.openai.com/api-keys)

---

## Setup

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

---

## Usage

```bash
python -m src.agent.main
```

### REPL commands

| Command  | Description                        |
|----------|------------------------------------|
| `/tools` | List available tools               |
| `/reset` | Clear the conversation history     |
| `/quit`  | Exit (also `Ctrl+C` / `Ctrl+D`)    |

---

## Available tools

| Tool                   | Description                                              |
|------------------------|----------------------------------------------------------|
| `get_current_datetime` | Returns the current UTC date and time                    |
| `calculator`           | Evaluates math expressions using Python's `math` module  |
| `web_search`           | Web search (mock results — replace with a real API)      |

---

## Architecture

```
main.py  ──►  Agent.chat()  ──►  OpenAI API
                  │
                  └──►  dispatch_tool()  ──►  tools.py
```

The `Agent` class (`src/agent/agent.py`) is kept free of any CLI or framework concerns, making it straightforward to integrate NeMo Guardrails as an interception layer between the user input and the agent without modifying the core logic.

---

## Roadmap

- [ ] Phase 1 — Base agentic application ✅
- [ ] Phase 2 — NeMo Guardrails integration
  - [ ] Input rails (topic restrictions, jailbreak detection)
  - [ ] Output rails (sensitive data filtering)
  - [ ] Guardrail configuration via Colang
