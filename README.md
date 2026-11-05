# Vault

> [!CAUTION]
> **Under Development — Untested.** This tool has not been validated in production engagements. Features may be incomplete, unstable, or produce unreliable results. Do not rely on its output for deliverables without independent verification.

Active Directory / SMB credential test orchestrator built on [impacket](https://github.com/fortra/impacket).

Vault is an **action-item-driven** tool — it picks up where Scattershot3's recon and Dredge's passive analysis leave off, running targeted credential-authenticated AD exploitation validation.


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/vault)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

### Credential Modules
- **secretsdump** — DCSync / SAM hash extraction via `secretsdump.py`
- **Kerberoasting** — TGS service ticket capture via `GetUserSPNs.py`
- **AS-REP Roasting** — Pre-auth disabled account hash capture via `GetNPUsers.py`
- **SMB signing** — Relay candidate detection via `rpcdump.py`

### Enumeration Modules
- **LDAP enum** — Domain user/group enumeration via `GetADUsers.py` + `ldapdomaindump`
- **SID enum** — SID brute-force enumeration via `lookupsid.py`
- **SAM dump** — Password policy and user enumeration via `samrdump.py`
- **Delegation** — Unconstrained/constrained/RBCD detection via `findDelegation.py`
- **SPN scan** — Service Principal Name inventory via `GetUserSPNs.py` (list mode)

### Exploitation Validation Modules
- **Pass-the-Hash exec** — Remote code execution validation via `wmiexec.py`/`psexec.py`/`smbexec.py`
- **DCOM exec** — DCOM-based remote execution via `dcomexec.py`
- **TGT request** — Credential validation via `getTGT.py`
- **Service ticket** — SPN access validation via `getST.py`
- **Share enum** — Authenticated share enumeration via `smbclient.py`
- **Registry secrets** — Auto-logon credential extraction via `reg.py`
- **GPP passwords** — SYSVOL cpassword extraction via `smbclient.py`

### Relay & Spray Modules
- **NTLM relay** — Relay attack validation via `ntlmrelayx.py`
- **Password spray** — AD password spraying via `getTGT.py` (with lockout protection)
- **DPAPI** — Domain backup key extraction via `dpapi.py`

### Authentication
- **Password auth** — Standard domain credentials (`--user` + `--password`)
- **Pass-the-hash** — NTLM hash authentication (`--hashes LMHASH:NTHASH`)
- **Kerberos ticket** — ccache-based authentication (`--ccache PATH`)
- **Multi-target** — Test multiple DCs from a targets file (`--targets-file`)

## Requirements

- Python 3.10+
- impacket >= 0.12.0 (0.13.0 recommended)
- ldapdomaindump >= 0.9.4 (optional, for LDAP enumeration)
- smbclient (system package)

## Installation

```bash
cd /opt/pr0t31n/Vault
python3 install.py
```

## Usage

```bash
# Run all modules against a single DC
python3 vault.py --target 10.0.0.1 --user admin --password 'P@ss' --domain corp.local

# Run module groups
python3 vault.py --target 10.0.0.1 --user admin --password 'P@ss' --domain corp.local \
    --modules credential                # secretsdump, kerberoast, asreproast, smb_relay
python3 vault.py --target 10.0.0.1 --user admin --password 'P@ss' --domain corp.local \
    --modules enum                      # ldap_enum, sid_enum, sam_dump, delegation, spn_scan
python3 vault.py --target 10.0.0.1 --user admin --password 'P@ss' --domain corp.local \
    --modules exec                      # pth_exec, dcom_exec, tgt_request, share_enum, etc.

# Cherry-pick modules
python3 vault.py --target 10.0.0.1 --user admin --password 'P@ss' --domain corp.local \
    --modules secretsdump,pth_exec,share_enum

# Pass-the-hash authentication
python3 vault.py --target 10.0.0.1 --user admin --hashes aad3b435b51404ee:da6e7d2a1b5e2b8e --domain corp.local

# Kerberos ticket-based authentication
python3 vault.py --target 10.0.0.1 --user admin --ccache /tmp/admin.ccache --domain corp.local

# Multi-target
python3 vault.py --targets-file dc_list.txt --user admin --password 'P@ss' --domain corp.local

# Password spraying with lockout protection
python3 vault.py --target 10.0.0.1 --domain corp.local --modules password_spray \
    --password-list passwords.txt --spray-delay 60 --lockout-threshold 3
```

## CLI Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | | Target DC / SMB host IP or hostname |
| `--targets-file` | | File with one target IP per line |
| `--user` | | Username |
| `--password` | | Password |
| `--hashes` | | NTLM hash in `LMHASH:NTHASH` format |
| `--ccache` | | Path to Kerberos ccache file |
| `--domain` | | AD domain / realm |
| `--users-file` | | User list for AS-REP roasting |
| `--modules` | `all` | Module names or groups (see below) |
| `--timeout` | `300` | Per-module timeout in seconds |
| `--spn` | | Target SPN for service_ticket module |
| `--password-list` | | Password list for spray module |
| `--spray-delay` | `30` | Seconds between spray rounds |
| `--lockout-threshold` | `5` | Max failures per account before stopping |
| `--client-short` | `default` | Client short name for output directory |
| `--client-name` | | Full client name for meta.json |
| `--engagement-name` | `vault run` | Engagement name |
| `--project` | | Override output directory path |
| `--version` | | Print version and exit |

## Module Groups

| Group | Modules |
|-------|---------|
| `all` | Every module |
| `credential` | secretsdump, kerberoast, asreproast, smb_relay |
| `enum` | ldap_enum, sid_enum, sam_dump, delegation, spn_scan |
| `exec` | pth_exec, dcom_exec, tgt_request, service_ticket, share_enum, reg_secrets, gpp_passwords |
| `relay` | ntlm_relay, password_spray, dpapi |

## Output

Follows the universal pr0t31n output structure:

```
<run_dir>/
├── meta.json              # Tool identity, version, engagement info
├── findings.json          # Universal schema findings
├── findings.csv           # CSV mirror
├── summary.json           # Aggregated statistics
├── scan.log               # Timestamped event log
├── errors.log             # Error-level entries
├── secretsdump.txt        # Module outputs (each with .log sibling)
├── kerberoast.txt
├── asreproast.txt
├── smb_signing.txt
├── lookupsid.txt
├── samrdump.txt
├── delegation.txt
├── spn_scan.txt
├── ldap_dump/             # ldapdomaindump evidence directory
├── pth_exec.txt
├── dcom_exec.txt
├── tgt.ccache             # Obtained TGT
├── service_ticket.ccache  # Obtained service ticket
├── share_enum.txt
├── reg_secrets.txt
├── gpp_passwords.txt
├── ntlm_relay.txt
├── password_spray.txt
└── dpapi_backupkeys.txt
```

Multi-target mode creates per-target subdirectories.

## Crucible Integration

Vault is managed by Crucible as an action-item-driven tool:

1. Scattershot3 discovers AD services (ports 88/389/636/3268)
2. Crucible's action engine creates a Vault action item (`ad_discovered` category)
3. Operator configures Vault credentials in project Settings
4. Vault runs in managed mode (`VAULT_MANAGED=1`)
5. Logs/status/findings stream to Crucible via `__VANTAGE_*__` tokens

Vault does **not** appear in the Crucible project wizard — it exists in the Settings tab only.

## Findings

### Credential Findings
| ID | Title | Risk |
|----|-------|------|
| VAULT-AD-001 | Credentials dumped via DCSync/SAM | CRITICAL |
| VAULT-AD-002 | Service tickets captured (Kerberoasting) | HIGH |
| VAULT-AD-003 | AS-REP roastable accounts found | HIGH |
| VAULT-AD-004 | SMB signing not required | MEDIUM |

### Enumeration Findings
| ID | Title | Risk |
|----|-------|------|
| VT-ENUM-001 | Domain users enumerated via LDAP | INFO |
| VT-ENUM-002 | Domain users enumerated via SID brute-force | INFO |
| VT-ENUM-003 | Weak password policy / no lockout | MEDIUM |
| VT-DELEG-001 | Kerberos delegation misconfiguration | HIGH |
| VT-ENUM-004 | Service Principal Names enumerated | INFO |

### Exploitation Findings
| ID | Title | Risk |
|----|-------|------|
| VT-EXEC-001 | Pass-the-Hash remote execution validated | CRITICAL |
| VT-EXEC-002 | DCOM remote execution validated | CRITICAL |
| VT-KERB-001 | TGT obtained with captured credentials | HIGH |
| VT-KERB-002 | Service ticket obtained for SPN | HIGH |
| VT-SMB-001 | Authenticated share access (ADMIN$/C$ writable = HIGH) | MEDIUM-HIGH |
| VT-REG-001 | Auto-logon credentials in registry | HIGH |
| VT-GPP-001 | GPP cpassword found in SYSVOL | CRITICAL |

### Relay & Spray Findings
| ID | Title | Risk |
|----|-------|------|
| VT-RELAY-001 | NTLM relay attack validated | CRITICAL |
| VT-SPRAY-001 | Password spray — credentials found | HIGH |
| VT-DPAPI-001 | DPAPI domain backup key extracted | HIGH |
