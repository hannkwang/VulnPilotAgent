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
# Triage only (default)
.venv/bin/python main.py CVE-2014-0160   # Heartbleed
.venv/bin/python main.py CVE-2021-44228  # Log4Shell

# Simulate patching without executing (safe)
.venv/bin/python main.py CVE-2014-0160 --patch --dry-run

# Live patching — admin prompted to authorize each command
.venv/bin/python main.py CVE-2014-0160 --patch
```

There are no tests or linters configured.

## Architecture

**Entry point:** `main.py` validates the CVE ID format (`^CVE-\d{4}-\d{4,}$`) and parses `--patch` / `--dry-run` flags, then calls `run_triage()` in `agent.py`. It contains no agent logic.

**Agentic loop:** `agent.py` (`run_triage()`) drives a `while True` loop calling `client.messages.create()` until `stop_reason == "end_turn"`. The Python code is purely mechanical — it executes whatever Claude requests and feeds results back. All decision-making happens inside Claude, not in the loop. Model and token budget are set as module-level constants (`MODEL`, `MAX_TOKENS`).

**Tool dispatch flow:**
1. Claude calls `fetch_cve` → `tools/fetch_cve.py` hits the NVD API v2.0 and returns structured text
2. Claude calls `check_epss` → `tools/check_epss.py` fetches EPSS score from FIRST and checks the CISA KEV catalog in a single call; returns both results concatenated
3. Claude calls `check_system` (once per affected product it deems relevant) → `tools/check_system.py` runs local system commands and returns what's installed
4. If `--patch` is active and triage is HIGH/CRITICAL, Claude calls `patch_system` → `tools/patch_system.py` runs package manager upgrade commands after interactive admin authorization
5. Claude reasons over the combined results and writes the final triage report

**Critical agentic loop invariants** (in `agent.py`):
- The full `response.content` list (not just text) must be appended as the assistant message — tool_use blocks must be preserved so the API can match them to tool_results
- All tool results for a single turn go back in **one** user message as a list of `{"type": "tool_result", "tool_use_id": block.id, "content": result}` blocks — `block.id` must match exactly
- Claude may request multiple tools in a single response; all are executed before sending results back

**Tool definitions** (`tool_definitions.py`) are raw JSON schema dicts passed directly to `client.messages.create(tools=...)`. The descriptions are what guide Claude's tool-calling strategy. `patch_system_tool_def` is only added to the tools list when `--patch` is active — it is hidden from Claude otherwise.

**System detection** (`tools/check_system.py`) tries five methods in order: macOS version check (`sw_vers`, for OS-level CVEs), binary version probe, Homebrew, pip, dpkg, rpm. All failures are silently swallowed — missing package managers are expected.
- `_MACOS_KEYWORDS` (shared set of 8 terms) triggers the `sw_vers` path. It is imported by `patch_system.py` to keep the two in sync.
- `_SW_VERS_CACHE` caches the `sw_vers` output so repeated macOS CVE checks don't fork a new process each time.
- macOS detection does **not** early-return — falls through to binary/brew/pip probes so a package coincidentally named `darwin` or `apple` is still checked.

**NVD parsing** (`tools/fetch_cve.py`): CVSS is read from `metrics.cvssMetricV31` first, falling back to `cvssMetricV30`; prefers `type == "Primary"` entries. CPE 2.3 URIs (`cpe:2.3:a:vendor:product:version:...`) are split on `:` to extract vendor (index 3) and product (index 4). Affected products are capped at 10 to avoid token bloat. Retries up to 3 times with backoff on 429/503.

**Patching** (`tools/patch_system.py`): tries softwareupdate (macOS OS-level), Homebrew, pip, apt-get, dnf/yum in sequence, skipping any not present. Each command requires interactive `y/N` authorization from the admin before executing. `dry_run=True` prints the command instead. Uses `Popen` line-by-line streaming (capped at 2000 chars) to avoid buffering large upgrade logs. Admin decline sets `declined = True` and stops all further prompts for that call.

**Logging** (`agent.py`, `_setup_logger()`): each `run_triage()` call creates a timestamped log file at `logs/<CVE-ID>_<YYYYMMDD_HHMMSS>.log`. The log captures: session metadata (CVE, mode, model), per-iteration headers with `stop_reason`, input/output token counts, and wall-clock latency, then each tool call with its full input dict and a 150-char result preview. The `logs/` directory is gitignored.

## External API Dependencies

| API | URL | Used for |
|-----|-----|----------|
| NVD v2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE details, CVSS, CPE |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | Exploit probability score |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Active exploitation status |

All three are unauthenticated public APIs over HTTPS. NVD has rate limits (429 triggers backoff); the other two do not.

## Adding a New Tool

Four files must change in lockstep:

1. **`tools/<name>.py`** — implement the function and return a plain string result
2. **`tool_definitions.py`** — add a JSON schema dict describing the tool's inputs
3. **`agent.py` `execute_tool()`** — add an `elif name == "<name>"` branch dispatching to the function
4. **`agent.py` `run_triage()`** — append the new `_tool_def` to the `tools` list (conditionally if it should be gated like `patch_system`)

The tool description in `tool_definitions.py` is what Claude reads to decide when and how to call the tool — keep it precise and action-oriented.

## Where the Autonomy Lives

The Python loop has no intelligence — it only runs tools on demand and loops. Claude is the autonomous actor. On every iteration, Claude decides:

- **Which tool to call** — the system prompt suggests fetching the CVE first, but nothing in the code enforces this
- **Which products to check** — Claude selects which affected products from the CPE list are worth checking, ignoring irrelevant entries (e.g. iOS/watchOS variants when triaging a desktop system)
- **How many `check_system` calls to make** — the code handles any number; Claude decides when it has enough information
- **Whether to patch** — if `patch_system` is available, Claude decides whether the triage warrants calling it and which `package_manager` hint to pass
- **When to stop** — no code tells Claude "you're done"; Claude decides when evidence is sufficient
- **The triage reasoning itself** — version comparison against the CVE's affected range happens in Claude's reasoning, not in Python

## Triage Logic

Defined entirely in the system prompt in `agent.py` (`_build_system_prompt()`). The mapping is CVSS score + whether affected software was found locally → CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL → P1–P4 priority. EPSS and KEV status can escalate the priority (KEV → minimum P2; EPSS ≥ 0.5 → minimum P2).
