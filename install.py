#!/usr/bin/env python3
"""Vault installer — multi-platform."""
import subprocess
import sys
import os
import shutil
from pathlib import Path

TOOL_NAME = "Vault"
MIN_PYTHON = (3, 10)


def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)


def _has(binary):
    return shutil.which(binary) is not None


def install_system_deps():
    """Install system packages via apt/brew/choco."""
    pkgs_apt = ["smbclient"]
    pkgs_brew = ["samba"]
    if sys.platform.startswith("linux") and _has("apt-get"):
        print("\n[*] Installing system dependencies (apt)...")
        _run(["sudo", "apt-get", "install", "-y"] + pkgs_apt)
    elif sys.platform == "darwin" and _has("brew"):
        print("\n[*] Installing system dependencies (brew)...")
        for pkg in pkgs_brew:
            _run(["brew", "install", pkg], check=False)


def install_pip_deps():
    """Always last. Always --break-system-packages."""
    print("\n[*] Installing Python dependencies...")
    req = Path(__file__).resolve().parent / "requirements.txt"
    if req.exists():
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages", "-r", str(req)])
    else:
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages", "impacket>=0.12.0",
              "ldapdomaindump>=0.9.4"])


def verify_impacket():
    """Verify impacket scripts are on PATH after install."""
    print("\n[*] Verifying impacket installation...")
    required = {
        "secretsdump.py": ["impacket-secretsdump", "secretsdump"],
        "GetUserSPNs.py": ["impacket-GetUserSPNs", "GetUserSPNs"],
        "GetNPUsers.py": ["impacket-GetNPUsers", "GetNPUsers"],
        "rpcdump.py": ["impacket-rpcdump", "rpcdump"],
        "GetADUsers.py": ["impacket-GetADUsers", "GetADUsers"],
        "lookupsid.py": ["impacket-lookupsid", "lookupsid"],
        "samrdump.py": ["impacket-samrdump", "samrdump"],
        "findDelegation.py": ["impacket-findDelegation", "findDelegation"],
        "wmiexec.py": ["impacket-wmiexec", "wmiexec"],
        "psexec.py": ["impacket-psexec", "psexec"],
        "smbexec.py": ["impacket-smbexec", "smbexec"],
        "dcomexec.py": ["impacket-dcomexec", "dcomexec"],
        "getTGT.py": ["impacket-getTGT", "getTGT"],
        "getST.py": ["impacket-getST", "getST"],
        "smbclient.py": ["impacket-smbclient", "smbclient"],
        "reg.py": ["impacket-reg", "reg"],
        "ntlmrelayx.py": ["impacket-ntlmrelayx", "ntlmrelayx"],
        "dpapi.py": ["impacket-dpapi", "dpapi"],
    }
    missing = []
    for script, alternatives in required.items():
        found = _has(script)
        if not found:
            for alt in alternatives:
                if _has(alt):
                    found = True
                    break
        if found:
            print(f"  ✓ {script}")
        else:
            print(f"  ✗ {script} — NOT FOUND")
            missing.append(script)
    if missing:
        print(f"\n[!] WARNING: {len(missing)} impacket script(s) not found on PATH.")
        print("    Try: pip3 install --break-system-packages impacket")
    else:
        print("  All impacket scripts verified.")

    if _has("ldapdomaindump"):
        print("  ✓ ldapdomaindump")
    else:
        print("  ✗ ldapdomaindump — NOT FOUND (optional, for LDAP enumeration)")

    if _has("kerbrute"):
        print("  ✓ kerbrute")
    else:
        print("  ✗ kerbrute — NOT FOUND (optional, for password spraying)")


def main():
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required")
        sys.exit(1)

    print(f"\n{'='*50}")
    print(f"  {TOOL_NAME} — Installation")
    print(f"{'='*50}")

    install_system_deps()
    install_pip_deps()
    verify_impacket()

    print(f"\n{'='*50}")
    print(f"  {TOOL_NAME} installed.")
    print(f"  Start with: python3 vault.py --help")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
