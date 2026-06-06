# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then set ANTHROPIC_API_KEY
```

## Running

```bash
# Activate venv first, or use .venv/bin/python directly
.venv/bin/python main.py CVE-YYYY-NNNNN

# Examples
.venv/bin/python main.py CVE-2014-0160   # Heartbleed
.venv/bin/python main.py CVE-2021-44228  # Log4Shell
```

## Architecture

**Entry point:** `main.py` validates the CVE ID format and calls `run_triage()` in `agent.py`. It contains no agent logic — just argument parsing and input validation.

**Agentic loop:** `agent.py` (`run_triage()`) drives a `while True` loop calling `client.messages.create()` until `stop_reason == "end_turn"`. The Python code is purely mechanical — it executes whatever Claude requests and feeds results back. All decision-making happens inside Claude, not in the loop.

**Tool dispatch flow:**
1. Claude calls `fetch_cve` → `tools/fetch_cve.py` hits the NVD API v2.0 and returns structured text
2. Claude calls `check_system` (once per affected product it deems relevant) → `tools/check_system.py` runs local system commands and returns what's installed
3. Claude reasons over the combined results and writes the final triage report

**Critical agentic loop invariants** (in `agent.py`):
- The full `response.content` list (not just text) must be appended as the assistant message — tool_use blocks must be preserved so the API can match them to tool_results
- All tool results for a single turn go back in **one** user message as a list of `{"type": "tool_result", "tool_use_id": block.id, "content": result}` blocks — `block.id` must match exactly
- Claude may request multiple tools in a single response; all are executed before sending results back

**Tool definitions** (`tool_definitions.py`) are raw JSON schema dicts passed directly to `client.messages.create(tools=...)`. The descriptions are what guide Claude's tool-calling strategy.

**System detection** (`tools/check_system.py`) tries five methods in order: macOS version check (sw_vers, for OS-level CVEs), binary version probe, Homebrew, pip, dpkg, rpm. All failures are silently swallowed — missing package managers are expected.

**NVD parsing** (`tools/fetch_cve.py`): CVSS lives at `metrics.cvssMetricV31[].cvssData`; prefers `type == "Primary"` entries. CPE 2.3 URIs (`cpe:2.3:a:vendor:product:version:...`) are split on `:` to extract vendor (index 3) and product (index 4). Affected products are capped at 10 to avoid token bloat.

## Where the Autonomy Lives

The Python loop has no intelligence — it only runs tools on demand and loops. Claude is the autonomous actor. On every iteration, Claude decides:

- **Which tool to call** — the system prompt suggests fetching the CVE first, but nothing in the code enforces this. Claude chooses.
- **Which products to check** — after reading the NVD response, Claude selects which affected products from the CPE list are worth checking on this machine. It may ignore irrelevant entries (e.g. skipping iOS/watchOS variants when triaging a desktop system).
- **How many `check_system` calls to make** — the code handles any number. Claude decides when it has enough information to stop gathering data.
- **When to stop using tools and write the report** — no code tells Claude "you're done." Claude decides when evidence is sufficient.
- **The triage reasoning itself** — Claude compares the detected version against the CVE's affected range and applies judgment. That comparison happens in Claude's reasoning, not in Python.

This is the key difference from a pipeline, which would hardcode the steps:
```python
# Pipeline (not what this is):
cve = fetch_cve(cve_id)
result = check_system(product)
triage = compute_triage(cve, result)  # logic in code
```
Here, all three steps — what to fetch, what to check, and how to decide — are delegated to Claude on each loop iteration.

## Triage Logic

Defined entirely in the system prompt in `agent.py` (`SYSTEM_PROMPT`). Claude decides the triage level — not code. The mapping is CVSS score + whether affected software was found locally → CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL → P1–P4 priority.
