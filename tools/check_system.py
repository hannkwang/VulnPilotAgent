import subprocess
import shutil
import platform


def check_system(product_name: str, vendor_name: str = "") -> str:
    results = []
    name = product_name.lower().strip()

    # 1. Binary version probe
    for flag in ("--version", "-v", "version"):
        try:
            r = subprocess.run(
                [name, flag], capture_output=True, text=True, timeout=5
            )
            out = (r.stdout + r.stderr).strip()
            if out and r.returncode in (0, 1):
                binary_path = shutil.which(name) or name
                results.append(f"Binary found: {binary_path}\nVersion output: {out[:200]}")
                break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    # 2. Homebrew (macOS)
    if platform.system() == "Darwin":
        try:
            r = subprocess.run(
                ["brew", "list", "--versions", name],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0 and r.stdout.strip():
                results.append(f"Homebrew: {r.stdout.strip()}")
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    # 3. Python packages (pip)
    try:
        r = subprocess.run(
            ["pip", "show", name],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            results.append(f"Python package (pip):\n{r.stdout.strip()[:300]}")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 4. dpkg (Debian/Ubuntu)
    try:
        r = subprocess.run(
            ["dpkg", "-l", f"*{name}*"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            lines = [l for l in r.stdout.splitlines() if l.startswith("ii")]
            if lines:
                results.append("dpkg:\n" + "\n".join(lines[:5]))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 5. rpm (RHEL/Fedora)
    try:
        r = subprocess.run(
            ["rpm", "-q", name],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip() and "not installed" not in r.stdout:
            results.append(f"rpm: {r.stdout.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    if not results:
        return (
            f"'{product_name}' not found on this system "
            f"(checked binary path, Homebrew, pip, dpkg, rpm)."
        )

    return f"Found '{product_name}' on this system:\n\n" + "\n\n".join(results)
