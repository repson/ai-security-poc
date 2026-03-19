.PHONY: help install install-dev test test-no-llm test-llm test-agents test-agents-no-llm test-llm-modules lint

# Default Python interpreter
PYTHON ?= python

# ── help ────────────────────────────────────────────────────────────────────

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Setup"
	@echo "  install          Install base dependencies (requirements.txt)"
	@echo "  install-dev      Install base + pytest dev tooling"
	@echo ""
	@echo "Tests (no API key required)"
	@echo "  test             Run all API-key-free pytest unit tests"
	@echo "  test-no-llm      Same as 'test' (alias)"
	@echo ""
	@echo "Tests (OPENAI_API_KEY required)"
	@echo "  test-llm         Run all LLM module exploit harnesses"
	@echo "  test-agents      Run all agentic module exploit harnesses"
	@echo ""
	@echo "Specific module suites (no API key required)"
	@echo "  test-agents-no-llm   Run exploit harnesses that need no API key"
	@echo "  test-llm-modules     Run LLM module harnesses that need no API key"
	@echo ""
	@echo "Other"
	@echo "  lint             Check for obvious issues with flake8 (if installed)"

# ── setup ───────────────────────────────────────────────────────────────────

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install "pytest>=8.0" "pytest-timeout>=2.3"

# ── pure-logic pytest suite (no OPENAI_API_KEY needed) ──────────────────────

test: install-dev
	$(PYTHON) -m pytest tests/ -m "no_llm" -v

test-no-llm: test

# ── exploit harnesses that need no API key ───────────────────────────────────

test-agents-no-llm:
	@echo "=== ASI05 Unexpected Code Execution ==="
	$(PYTHON) -m src.agents.asi05_unexpected_code_execution.exploits.run_tests
	@echo "=== ASI06 Memory & Context Poisoning ==="
	$(PYTHON) -m src.agents.asi06_memory_context_poisoning.exploits.run_tests
	@echo "=== ASI08 Cascading Failures ==="
	$(PYTHON) -m src.agents.asi08_cascading_failures.exploits.run_tests
	@echo "=== ASI10 Rogue Agents ==="
	$(PYTHON) -m src.agents.asi10_rogue_agents.exploits.run_tests

test-llm-modules:
	@echo "=== LLM03 Supply Chain ==="
	$(PYTHON) -m src.llm.llm03_supply_chain.exploits.run_tests
	@echo "=== LLM04 Data & Model Poisoning ==="
	$(PYTHON) -m src.llm.llm04_data_model_poisoning.exploits.run_tests

# ── exploit harnesses that require OPENAI_API_KEY ───────────────────────────

test-llm:
	@if [ -z "$$OPENAI_API_KEY" ]; then \
		echo "ERROR: OPENAI_API_KEY is not set."; exit 1; \
	fi
	@echo "=== LLM01 Prompt Injection ==="
	$(PYTHON) -m src.llm.llm01_prompt_injection.exploits.run_tests
	@echo "=== LLM02 Sensitive Information Disclosure ==="
	$(PYTHON) -m src.llm.llm02_sensitive_information.exploits.run_tests
	@echo "=== LLM05 Improper Output Handling ==="
	$(PYTHON) -m src.llm.llm05_improper_output_handling.exploits.run_tests
	@echo "=== LLM06 Excessive Agency ==="
	$(PYTHON) -m src.llm.llm06_excessive_agency.exploits.run_tests
	@echo "=== LLM07 System Prompt Leakage ==="
	$(PYTHON) -m src.llm.llm07_system_prompt_leakage.exploits.run_tests
	@echo "=== LLM08 Vector & Embedding Weaknesses ==="
	$(PYTHON) -m src.llm.llm08_vector_embedding_weaknesses.exploits.run_tests
	@echo "=== LLM09 Misinformation ==="
	$(PYTHON) -m src.llm.llm09_misinformation.exploits.run_tests
	@echo "=== LLM10 Unbounded Consumption ==="
	$(PYTHON) -m src.llm.llm10_unbounded_consumption.exploits.run_tests

test-agents:
	@if [ -z "$$OPENAI_API_KEY" ]; then \
		echo "ERROR: OPENAI_API_KEY is not set."; exit 1; \
	fi
	@echo "=== ASI01 Agent Goal Hijack ==="
	$(PYTHON) -m src.agents.asi01_agent_goal_hijack.exploits.run_tests
	@echo "=== ASI02 Tool Misuse ==="
	$(PYTHON) -m src.agents.asi02_tool_misuse.exploits.run_tests
	@echo "=== ASI03 Identity & Privilege Abuse ==="
	$(PYTHON) -m src.agents.asi03_identity_privilege_abuse.exploits.run_tests
	@echo "=== ASI04 Agentic Supply Chain ==="
	$(PYTHON) -m src.agents.asi04_supply_chain.exploits.run_tests
	@echo "=== ASI05 Unexpected Code Execution ==="
	$(PYTHON) -m src.agents.asi05_unexpected_code_execution.exploits.run_tests
	@echo "=== ASI06 Memory & Context Poisoning ==="
	$(PYTHON) -m src.agents.asi06_memory_context_poisoning.exploits.run_tests
	@echo "=== ASI07 Insecure Inter-Agent Communication ==="
	$(PYTHON) -m src.agents.asi07_insecure_interagent_communication.exploits.run_tests
	@echo "=== ASI08 Cascading Failures ==="
	$(PYTHON) -m src.agents.asi08_cascading_failures.exploits.run_tests
	@echo "=== ASI09 Human-Agent Trust ==="
	$(PYTHON) -m src.agents.asi09_human_agent_trust.exploits.run_tests
	@echo "=== ASI10 Rogue Agents ==="
	$(PYTHON) -m src.agents.asi10_rogue_agents.exploits.run_tests

# ── lint (optional) ──────────────────────────────────────────────────────────

lint:
	@$(PYTHON) -m flake8 src/ tests/ --max-line-length=120 --extend-ignore=E501 2>/dev/null || \
		echo "(flake8 not installed — skipping lint)"
