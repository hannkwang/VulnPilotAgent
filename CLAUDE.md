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

The agent follows a **manual Anthropic agentic loop**: `main.py` validates input and calls `run_triage()` in `agent.py`, which drives a `while True` loop calling `client.messages.create()` until `stop_reason == "end_turn"`.

**Tool dispatch flow:**
1. Claude calls `fetch_cve` → `tools/fetch_cve.py` hits the NVD API v2.0 and returns structured text
2. Claude calls `check_system` (once per affected product) → `tools/check_system.py` runs local system commands and returns what's installed
3. Claude reasons over the combined results and writes the final triage report

**Critical agentic loop invariants** (in `agent.py`):
- The full `response.content` list (not just text) must be appended as the assistant message — tool_use blocks must be preserved so the API can match them to tool_results
- All tool results for a single turn go back in **one** user message as a list of `{"type": "tool_result", "tool_use_id": block.id, "content": result}` blocks — `block.id` must match exactly
- Claude may request multiple tools in a single response; all are executed before sending results back

**Tool definitions** (`tool_definitions.py`) are raw JSON schema dicts passed directly to `client.messages.create(tools=...)`. The descriptions are what guide Claude's tool-calling strategy.

**System detection** (`tools/check_system.py`) tries five methods in order: binary version probe, Homebrew, pip, dpkg, rpm. All failures are silently swallowed — missing package managers are expected.

**NVD parsing** (`tools/fetch_cve.py`): CVSS lives at `metrics.cvssMetricV31[].cvssData`; prefers `type == "Primary"` entries. CPE 2.3 URIs (`cpe:2.3:a:vendor:product:version:...`) are split on `:` to extract vendor (index 3) and product (index 4). Affected products are capped at 10 to avoid token bloat.

## Triage Logic

Defined entirely in the system prompt in `agent.py` (`SYSTEM_PROMPT`). Claude decides the triage level — not code. The mapping is CVSS score + whether affected software was found locally → CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL → P1–P4 priority.
