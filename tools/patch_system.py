import subprocess
import platform
import shutil

from tools.check_system import _MACOS_KEYWORDS  # shared — keeps keyword sets in sync


def patch_system(product_name: str, package_manager: str = "", dry_run: bool = False) -> str:
    name = product_name.lower().strip()
    pm = package_manager.lower().strip()
    # Snapshot dry_run into a local so the closure always sees this call's value,
    # regardless of any concurrent caller.
    _dry_run = dry_run
    declined = False  # set True when admin says N; stops further prompts
    results = []

    # Reject flag-like names before they reach any subprocess call.
    if name.startswith("-"):
        return f"Rejected: '{product_name}' looks like a flag and cannot be passed safely to a package manager."

    def run(cmd: list) -> str:
        nonlocal declined
        if _dry_run:
            return f"[DRY RUN] Would run: {' '.join(cmd)}"
        print(f"\n  Proposed patch command: {' '.join(cmd)}")
        try:
            answer = input("  Authorize this patch? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            declined = True
            return "Patch declined by admin — command not executed."
        # Stream output to avoid buffering large upgrade logs (e.g. brew upgrade llvm) in RAM.
        try:
            with subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            ) as proc:
                out_buf = []
                total = 0
                for line in proc.stdout:
                    out_buf.append(line)
                    total += len(line)
                    if total >= 2000:
                        proc.kill()
                        break
                _, err = proc.communicate()
                combined = ("".join(out_buf) + err).strip()
                rc = proc.returncode if proc.returncode is not None else -1
            if rc == 0:
                return f"Success:\n{combined[:500]}"
            return f"Failed (exit {rc}):\n{combined[:300]}"
        except subprocess.TimeoutExpired:
            return "Timed out after 120s."
        except (FileNotFoundError, OSError) as e:
            return f"Command not available: {e}"

    # macOS software update (for OS-level CVEs)
    if not declined and platform.system() == "Darwin" and (
        pm == "softwareupdate" or name in _MACOS_KEYWORDS
    ):
        cmd = (
            ["softwareupdate", "--install", "--all"]
            if name in _MACOS_KEYWORDS
            else ["softwareupdate", "--install", name]
        )
        results.append(f"softwareupdate: {run(cmd)}")

    # Homebrew (macOS)
    if not declined and platform.system() == "Darwin" and pm in ("", "brew", "homebrew"):
        if shutil.which("brew"):
            results.append(f"Homebrew: {run(['brew', 'upgrade', name])}")

    # pip
    if not declined and pm in ("", "pip"):
        if shutil.which("pip"):
            results.append(f"pip: {run(['pip', 'install', '--upgrade', name])}")

    # apt (Debian/Ubuntu)
    if not declined and pm in ("", "apt", "apt-get"):
        if shutil.which("apt-get"):
            results.append(
                f"apt-get: {run(['sudo', 'apt-get', 'install', '--only-upgrade', '-y', name])}"
            )

    # dnf/yum (RHEL/Fedora)
    if not declined and pm in ("", "dnf", "rpm"):
        mgr = shutil.which("dnf") or shutil.which("yum")
        if mgr:
            results.append(f"{mgr}: {run([mgr, 'update', '-y', name])}")

    if not results:
        return f"No suitable package manager found to patch '{product_name}'."

    return f"Patch attempt for '{product_name}':\n\n" + "\n\n".join(results)
