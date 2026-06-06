import os
import platform
import warnings
warnings.filterwarnings("ignore", category=Warning, module="urllib3")
from anthropic import Anthropic
from dotenv import load_dotenv

from tool_definitions import fetch_cve_tool_def, check_system_tool_def, patch_system_tool_def
from tools.fetch_cve import fetch_cve
from tools.check_system import check_system
from tools.patch_system import patch_system
import tools.patch_system as _patch_module

load_dotenv()

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096


def _get_os_info() -> str:
    if platform.system() == "Darwin":
        mac_ver = platform.mac_ver()[0]
        if mac_ver:
            return f"macOS {mac_ver} ({platform.machine()})"
    return f"{platform.system()} {platform.release()} ({platform.machine()})"

_OS_INFO = _get_os_info()


def _build_system_prompt(patch_enabled: bool, dry_run: bool) -> str:
    if patch_enabled:
        mode = "PATCH MODE (auto-patch HIGH/CRITICAL findings)"
        if dry_run:
            mode += " [DRY RUN — commands will be shown but not executed]"
    else:
        mode = "TRIAGE ONLY MODE (no patching)"

    patch_instructions = ""
    if patch_enabled:
        patch_instructions = """
If triage decision is HIGH or CRITICAL:
4. Call patch_system for each affected package found locally.
   - Pass package_manager hint based on how check_system found it
     (e.g. if check_system showed "Homebrew: openssl@3 ...", pass package_manager='brew').
   - The admin will be prompted to authorize each patch interactively.
5. After patching, call check_system again to verify the new installed version.
6. Include patch outcome (authorized/declined, old→new version) in the triage report.
"""

    return f"""You are a cybersecurity analyst performing CVE triage on the local machine.

System: {_OS_INFO}
Mode: {mode}

Your steps:
1. Call fetch_cve to get the full vulnerability details for the requested CVE ID.
2. For each distinct product listed in the CVE's affected products, call check_system to detect
   whether it is installed on this machine. Focus on the most common product names (e.g. 'openssl',
   'nginx', 'python') — not every CPE entry, just the unique software packages.
3. Based on the CVSS score and which affected software was actually found, produce a triage decision.
{patch_instructions}
Triage decision:
- CRITICAL: CVSS >= 9.0 AND affected software found locally
- HIGH:     CVSS >= 7.0 AND affected software found locally
- MEDIUM:   CVSS >= 4.0 AND affected software found locally
- LOW:      CVSS < 4.0 AND affected software found, OR software found but version not in affected range
- INFORMATIONAL: No affected software found on this system

Remediation priority:
- P1 (24 hours):   CRITICAL
- P2 (72 hours):   HIGH
- P3 (2 weeks):    MEDIUM
- P4 (next cycle): LOW / INFORMATIONAL

End your response with the following structured report:

CVE TRIAGE REPORT
================
CVE ID: [CVE-XXXX-XXXX]
CVSS Score: [score] ([severity])
Description: [one-sentence summary]
Affected Software Found Locally: [list with detected versions, or "None found on this system"]
TRIAGE DECISION: [CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL]
REMEDIATION PRIORITY: [P1/P2/P3/P4]
PATCH STATUS: [patched/declined/not applicable — only if PATCH MODE]
RECOMMENDED ACTIONS: [specific patch or mitigation steps]
TIMELINE: [concrete deadline based on priority]
"""


def execute_tool(name: str, tool_input: dict) -> str:
    if name == "fetch_cve":
        return fetch_cve(tool_input["cve_id"])
    elif name == "check_system":
        return check_system(
            product_name=tool_input["product_name"],
            vendor_name=tool_input.get("vendor_name", ""),
        )
    elif name == "patch_system":
        return patch_system(
            product_name=tool_input["product_name"],
            package_manager=tool_input.get("package_manager", ""),
        )
    return f"Unknown tool: {name}"


def run_triage(cve_id: str, patch_enabled: bool = False, dry_run: bool = False) -> str:
    # Propagate dry_run to the patch module
    _patch_module.DRY_RUN = dry_run

    # Build tool list — only expose patch_system when patching is enabled
    tools = [fetch_cve_tool_def, check_system_tool_def]
    if patch_enabled:
        tools.append(patch_system_tool_def)

    system_prompt = _build_system_prompt(patch_enabled, dry_run)
    client = Anthropic()
    messages = [{"role": "user", "content": f"Triage {cve_id}"}]

    mode_label = ""
    if patch_enabled:
        mode_label = " [DRY RUN]" if dry_run else " [PATCH MODE]"
    print(f"Starting triage for {cve_id}{mode_label}...\n")

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            tools=tools,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            for block in response.content:
                if block.type == "text":
                    return block.text
            return "No text response produced."

        if response.stop_reason == "max_tokens":
            for block in response.content:
                if block.type == "text":
                    return block.text + "\n\n[Response truncated — increase MAX_TOKENS]"
            return "[Response truncated at token limit]"

        if response.stop_reason == "tool_use":
            # Append the full assistant message (tool_use blocks must be preserved)
            messages.append({"role": "assistant", "content": response.content})

            # Execute all tool calls and collect results in one user message
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"  Tool: {block.name}  Input: {block.input}")
                    result = execute_tool(block.name, block.input)
                    preview = result[:150] + "..." if len(result) > 150 else result
                    print(f"  Result: {preview}\n")
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            messages.append({"role": "user", "content": tool_results})
            continue

        # Unexpected stop reason — return whatever text is available
        for block in response.content:
            if block.type == "text":
                return block.text
        return f"Agent stopped unexpectedly: {response.stop_reason}"
