import os
import warnings
warnings.filterwarnings("ignore", category=Warning, module="urllib3")
from anthropic import Anthropic
from dotenv import load_dotenv

from tool_definitions import fetch_cve_tool_def, check_system_tool_def
from tools.fetch_cve import fetch_cve
from tools.check_system import check_system

load_dotenv()

TOOLS = [fetch_cve_tool_def, check_system_tool_def]
MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096

SYSTEM_PROMPT = """You are a cybersecurity analyst performing CVE triage on the local machine.

Your steps:
1. Call fetch_cve to get the full vulnerability details for the requested CVE ID.
2. For each distinct product listed in the CVE's affected products, call check_system to detect
   whether it is installed on this machine. Focus on the most common product names (e.g. 'openssl',
   'nginx', 'python') — not every CPE entry, just the unique software packages.
3. Based on the CVSS score and which affected software was actually found, produce a triage decision.

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
    return f"Unknown tool: {name}"


def run_triage(cve_id: str) -> str:
    client = Anthropic()
    messages = [{"role": "user", "content": f"Triage {cve_id}"}]

    print(f"Starting triage for {cve_id}...\n")

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
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
