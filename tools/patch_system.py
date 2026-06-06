import subprocess
import platform
import shutil

DRY_RUN = False  # overridden by agent.py at startup


def patch_system(product_name: str, package_manager: str = "") -> str:
    name = product_name.lower().strip()
    pm = package_manager.lower().strip()
    results = []

    def run(cmd: list) -> str:
        if DRY_RUN:
            return f"[DRY RUN] Would run: {' '.join(cmd)}"
        print(f"\n  Proposed patch command: {' '.join(cmd)}")
        try:
            answer = input("  Authorize this patch? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            return "Patch declined by admin — command not executed."
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            out = (r.stdout + r.stderr).strip()
            if r.returncode == 0:
                return f"Success:\n{out[:500]}"
            return f"Failed (exit {r.returncode}):\n{out[:300]}"
        except subprocess.TimeoutExpired:
            return "Timed out after 120s."
        except (FileNotFoundError, OSError) as e:
            return f"Command not available: {e}"

    # macOS software update (for OS-level CVEs)
    if platform.system() == "Darwin" and (pm == "softwareupdate" or name in {"macos", "darwin", "apple"}):
        if name in {"macos", "darwin", "apple"}:
            cmd = ["softwareupdate", "--install", "--all"]
        else:
            cmd = ["softwareupdate", "--install", name]
        results.append(f"softwareupdate: {run(cmd)}")

    # Homebrew (macOS)
    if platform.system() == "Darwin" and pm in ("", "brew", "homebrew"):
        if shutil.which("brew"):
            results.append(f"Homebrew: {run(['brew', 'upgrade', name])}")

    # pip
    if pm in ("", "pip"):
        if shutil.which("pip"):
            results.append(f"pip: {run(['pip', 'install', '--upgrade', name])}")

    # apt (Debian/Ubuntu)
    if pm in ("", "apt", "apt-get"):
        if shutil.which("apt-get"):
            results.append(f"apt-get: {run(['sudo', 'apt-get', 'install', '--only-upgrade', '-y', name])}")

    # dnf/yum (RHEL/Fedora)
    if pm in ("", "dnf", "rpm"):
        mgr = shutil.which("dnf") or shutil.which("yum")
        if mgr:
            results.append(f"{mgr}: {run([mgr, 'update', '-y', name])}")

    if not results:
        return f"No suitable package manager found to patch '{product_name}'."

    prefix = "[DRY RUN] " if DRY_RUN else ""
    return f"{prefix}Patch attempt for '{product_name}':\n\n" + "\n\n".join(results)
