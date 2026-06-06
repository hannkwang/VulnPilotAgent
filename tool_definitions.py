fetch_cve_tool_def = {
    "name": "fetch_cve",
    "description": (
        "Fetch detailed vulnerability information for a CVE ID from the National "
        "Vulnerability Database (NVD). Returns description, CVSS v3 score, severity, "
        "CWE weakness IDs, and a list of affected CPE products. Call this first."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "The CVE identifier, e.g. 'CVE-2024-1234'.",
            }
        },
        "required": ["cve_id"],
    },
}

check_system_tool_def = {
    "name": "check_system",
    "description": (
        "Check whether a software product is installed on the local machine by running "
        "real system commands (binary probe, Homebrew, pip, dpkg, rpm). Call this for "
        "each distinct product found in the CVE's affected list. Returns version info "
        "if found, or 'not found' if absent."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "product_name": {
                "type": "string",
                "description": "Product or binary name to check, e.g. 'openssl', 'nginx', 'python'.",
            },
            "vendor_name": {
                "type": "string",
                "description": "Optional vendor name for additional context.",
            },
        },
        "required": ["product_name"],
    },
}

patch_system_tool_def = {
    "name": "patch_system",
    "description": (
        "Apply a patch or upgrade for a software package on the local machine. "
        "Only call this when the triage decision is HIGH or CRITICAL and patching is enabled. "
        "Uses the appropriate package manager (Homebrew, pip, apt, dnf, softwareupdate). "
        "The admin will be prompted to authorize each patch before it executes. "
        "Pass package_manager as a hint if check_system already revealed how the package is installed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "product_name": {
                "type": "string",
                "description": "Package name to upgrade, e.g. 'openssl', 'nginx', 'python3'.",
            },
            "package_manager": {
                "type": "string",
                "description": "Optional hint: 'brew', 'pip', 'apt', 'dnf', or 'softwareupdate'. Leave empty to try all.",
            },
        },
        "required": ["product_name"],
    },
}
