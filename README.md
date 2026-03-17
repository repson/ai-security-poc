# AI Security PoC

A hands-on reference implementation covering the **OWASP Top 10 for LLM Applications 2025** and the **OWASP Top 10 for Agentic Applications 2026**. Each risk has its own self-contained module with a vulnerable example application, working attack tools, and a mitigated implementation with full technical documentation.

---

## Reference frameworks

| Framework | Version | Risks | Official reference |
|---|---|---|---|
| OWASP Top 10 for LLM Applications | 2025 | LLM01–LLM10 | [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/) |
| OWASP Top 10 for Agentic Applications | 2026 | ASI01–ASI10 | [genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |

---

## OWASP LLM Top 10 (2025) coverage

| ID | Risk | Mitigation tools | Module | Status |
|---|---|---|---|---|
| LLM01 | Prompt Injection | NeMo Guardrails · garak · promptfoo | [llm01_prompt_injection](src/llm/llm01_prompt_injection/README.md) | ✅ done |
| LLM02 | Sensitive Information Disclosure | NeMo Guardrails · Microsoft Presidio · guardrails-ai | [llm02_sensitive_information](src/llm/llm02_sensitive_information/README.md) | ✅ done |
| LLM03 | Supply Chain Vulnerabilities | pip-audit · Syft · Grype · CycloneDX | [llm03_supply_chain](src/llm/llm03_supply_chain/README.md) | 🔜 planned |
| LLM04 | Data & Model Poisoning | garak · dataset checksums · embedding drift monitoring | [llm04_data_model_poisoning](src/llm/llm04_data_model_poisoning/README.md) | 🔜 planned |
| LLM05 | Improper Output Handling | guardrails-ai · Pydantic · bleach · parameterized queries | [llm05_improper_output_handling](src/llm/llm05_improper_output_handling/README.md) | 🔜 planned |
| LLM06 | Excessive Agency | agent-governance-toolkit · human-in-the-loop pattern · tool allowlist | [llm06_excessive_agency](src/llm/llm06_excessive_agency/README.md) | 🔜 planned |
| LLM07 | System Prompt Leakage | NeMo Guardrails · guardrails-ai · prompt hardening | [llm07_system_prompt_leakage](src/llm/llm07_system_prompt_leakage/README.md) | 🔜 planned |
| LLM08 | Vector & Embedding Weaknesses | ChromaDB ACL · RAGuard · perplexity filtering · access control | [llm08_vector_embedding_weaknesses](src/llm/llm08_vector_embedding_weaknesses/README.md) | 🔜 planned |
| LLM09 | Misinformation | NeMo Guardrails · garak · RAG grounding · confidence thresholds | [llm09_misinformation](src/llm/llm09_misinformation/README.md) | ✅ done |
| LLM10 | Unbounded Consumption | slowapi · redis · token budget middleware · circuit breakers | [llm10_unbounded_consumption](src/llm/llm10_unbounded_consumption/README.md) | 🔜 planned |

---

## OWASP Agentic AI Top 10 (2026) coverage

| ID | Risk | Mitigation tools | Module | Status |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | NeMo Guardrails · canary tokens · goal integrity checks | [asi01_agent_goal_hijack](src/agents/asi01_agent_goal_hijack/README.md) | 🔜 planned |
| ASI02 | Tool Misuse & Exploitation | agent-governance-toolkit · tool allowlist · parameter validation | [asi02_tool_misuse](src/agents/asi02_tool_misuse/README.md) | 🔜 planned |
| ASI03 | Identity & Privilege Abuse | OAuth 2.0 · short-lived tokens · zero-trust inter-agent | [asi03_identity_privilege_abuse](src/agents/asi03_identity_privilege_abuse/README.md) | 🔜 planned |
| ASI04 | Agentic Supply Chain Vulnerabilities | pip-audit · MCP server allowlist · Syft · signature verification | [asi04_supply_chain](src/agents/asi04_supply_chain/README.md) | 🔜 planned |
| ASI05 | Unexpected Code Execution (RCE) | RestrictedPython · subprocess sandboxing · seccomp · no eval/exec | [asi05_unexpected_code_execution](src/agents/asi05_unexpected_code_execution/README.md) | 🔜 planned |
| ASI06 | Memory & Context Poisoning | RAGuard · embedding anomaly detection · ChromaDB ACL · perplexity filtering | [asi06_memory_context_poisoning](src/agents/asi06_memory_context_poisoning/README.md) | 🔜 planned |
| ASI07 | Insecure Inter-Agent Communication | message signing · TLS · replay protection · agent identity registry | [asi07_insecure_interagent_communication](src/agents/asi07_insecure_interagent_communication/README.md) | 🔜 planned |
| ASI08 | Cascading Failures | circuit breakers · timeout budgets · blast radius limits | [asi08_cascading_failures](src/agents/asi08_cascading_failures/README.md) | 🔜 planned |
| ASI09 | Human-Agent Trust Exploitation | human-in-the-loop · confirmation gates · authority bias detection | [asi09_human_agent_trust](src/agents/asi09_human_agent_trust/README.md) | 🔜 planned |
| ASI10 | Rogue Agents | kill switches · behavior monitoring · delegation chain limits | [asi10_rogue_agents](src/agents/asi10_rogue_agents/README.md) | 🔜 planned |

---

## Shared base infrastructure

The `src/agent/` and `src/guardrails/` directories contain the shared base components reused across modules:

| Component | Path | Description |
|---|---|---|
| Base agent | `src/agent/` | Unprotected conversational agent with tool-calling loop (OpenAI) |
| NeMo Guardrails integration | `src/guardrails/` | Middleware security wrapper covering LLM01, LLM02, LLM07, LLM09 |

See [`src/guardrails/README.md`](src/guardrails/README.md) for the full technical documentation of the NeMo Guardrails integration: pipeline architecture, Colang flows, custom actions, and extension guide.

---

## Requirements

- Python 3.11+
- An [OpenAI API key](https://platform.openai.com/api-keys)

Additional per-module dependencies are listed in each module's `README.md`.

---

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 2. Install base dependencies
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

---

## Project structure

```
ai-security-poc/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
│
└── src/
    ├── agent/                                   # Shared base: unprotected agent
    │   ├── agent.py
    │   ├── tools.py
    │   └── main.py
    │
    ├── guardrails/                              # Shared base: NeMo Guardrails wrapper
    │   ├── README.md                            # Full technical documentation
    │   ├── guardrails_agent.py
    │   ├── actions.py
    │   ├── audit.py
    │   ├── main.py
    │   └── config/
    │       ├── config.yml
    │       └── rails.co
    │
    ├── llm/                                     # OWASP LLM Top 10 (2025)
    │   ├── llm01_prompt_injection/
    │   │   ├── README.md
    │   │   ├── vulnerable/
    │   │   ├── mitigated/
    │   │   └── exploits/
    │   ├── llm02_sensitive_information/
    │   ├── llm03_supply_chain/
    │   ├── llm04_data_model_poisoning/
    │   ├── llm05_improper_output_handling/
    │   ├── llm06_excessive_agency/
    │   ├── llm07_system_prompt_leakage/
    │   ├── llm08_vector_embedding_weaknesses/
    │   ├── llm09_misinformation/
    │   └── llm10_unbounded_consumption/
    │
    └── agents/                                  # OWASP Agentic AI Top 10 (2026)
        ├── asi01_agent_goal_hijack/
        │   ├── README.md
        │   ├── vulnerable/
        │   ├── mitigated/
        │   └── exploits/
        ├── asi02_tool_misuse/
        ├── asi03_identity_privilege_abuse/
        ├── asi04_supply_chain/
        ├── asi05_unexpected_code_execution/
        ├── asi06_memory_context_poisoning/
        ├── asi07_insecure_interagent_communication/
        ├── asi08_cascading_failures/
        ├── asi09_human_agent_trust/
        └── asi10_rogue_agents/
```

---

## Running the existing modules

| Module | Command | Description |
|---|---|---|
| Base agent (no protection) | `python -m src.agent.main` | Baseline agent — no security controls |
| Guarded agent (NeMo Guardrails) | `python -m src.guardrails.main` | LLM01 · LLM02 · LLM07 · LLM09 mitigations active |
