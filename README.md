# Painfree

A read-only Windows troubleshooter. One PowerShell command scans the machine's event logs, program logs, services, disks, registry, security settings, installed programs and any server roles it finds, then writes an HTML report with a proposed fix for every finding.

**Painfree never changes anything.** Each fix comes with steps and an example command for you to review and run yourself.

## Run it

Open PowerShell **as Administrator** and run:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; irm https://raw.githubusercontent.com/kconsulting786/painfree/main/painfree.ps1 | iex
```

The report opens in your browser when the scan finishes. It is saved to the Desktop as `Painfree-<COMPUTER>-<date>.html`, with a `.json` copy of the raw data next to it.

To pass options, use this form:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/kconsulting786/painfree/main/painfree.ps1))) -Days 14 -NoOpen -OutputPath C:\Reports
```

| Option | What it does |
|---|---|
| `-Days <n>` | How many days of logs to look back over (default 7). |
| `-OutputPath <path>` | File or folder to write the report to (default: Desktop). |
| `-NoOpen` | Don't open the report when done (handy on Server Core). |
| `-Quick` | Skip the slower checks: program log scan, folder sizes and dcdiag. |
| `-Upload` | Also upload the report to a private GitHub repo for later analysis (see below). |
| `-UploadRepo <owner/repo>` | Repo to upload to (default `kconsulting786/painfree-results`). Must be private. |
| `-UploadToken <token>` | GitHub token for the upload. If left out, Painfree uses `$env:PAINFREE_TOKEN`, then a token saved on the machine, and otherwise asks for it with hidden input. |
| `-SaveToken` | Use with `-Upload`: saves the token on this machine, encrypted, so later `-Upload` runs don't ask for it. |
| `-ClearToken` | Deletes the saved token from this machine and exits. |

## Uploading results for analysis

Painfree can push each report to a **private** GitHub repo so the results can be reviewed in depth later. It refuses to upload to a public repo.

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/kconsulting786/painfree/main/painfree.ps1))) -Upload
```

To stop being asked for the token on a machine, run once with `-Upload -SaveToken`. The token is encrypted with Windows DPAPI (machine scope, so scheduled tasks running as SYSTEM can use it) and stored in `C:\ProgramData\Painfree\upload-token.bin`, in a folder only Administrators and SYSTEM can read. After that, plain `-Upload` uses it. For RMM tools, set the `PAINFREE_TOKEN` environment variable instead. The token is never stored in the script: the script is public, so a token embedded in it, even an encrypted one, could be used by anyone.

Each scan is saved to `results/<COMPUTER>/<yyyy-MM-dd_HHmm>/report.json` and `report.html` in the results repo. Unless you use `-SaveToken`, the token is only used for that run and is never written to disk.

One-time setup:

1. Create a private repo, for example `painfree-results`.
2. Copy the contents of [`results-repo/`](results-repo/) into it. This includes a daily GitHub Action that deletes scans older than 3 days and squashes the history, so old scans don't stay in git either.
3. Create a [fine-grained personal access token](https://github.com/settings/personal-access-tokens/new) that has access to **only** that repository, with **Contents: Read and write** permission, and a short expiry.

## Supported systems

Windows 10, Windows 11, and Windows Server 2016, 2019, 2022 and 2025, using the built-in Windows PowerShell 5.1 or later. Nothing has to be installed.

## What it checks

| Area | Checks |
|---|---|
| Updates | Windows version end of support, RMM-managed patching recognised (Datto, NinjaOne, ConnectWise, N-able, Kaseya, Atera, Intune), last update installed, failed updates, Windows Update disabled or blocked by policy, pending reboot |
| Event logs | System, Application, Defender and role logs: about 70 known problem events with specific fixes (unexpected shutdowns, blue screens, disk and controller errors, NTFS corruption, service failures, DNS and domain problems, hardware WHEA errors, VSS, Group Policy, Secure Boot certificates, and more), plus any other recurring errors and repeated application crashes |
| Security log | Failed logon floods, grouped by account and source address |
| Power | Unexpected restarts while the UPS agent (APC PowerChute) can't reach the UPS; servers with power losses and no UPS shutdown software |
| Disks | Low free space, unhealthy disks, SMART failure prediction, SSD wear, uncorrected errors, temperature, volumes marked dirty, things that are safe to clean up |
| Performance | Memory and CPU pressure, page file, low RAM, server power plan, too many startup programs |
| Hardware | Devices with driver problems, crash dumps, Windows Error Reporting crash reports |
| Services and tasks | Automatic services that are stopped, services and scheduled tasks pointing to missing programs, failed scheduled tasks, unquoted service paths |
| Registry | Broken startup entries, Winlogon Shell/Userinit hijacks, IFEO debugger hijacks, AppInit_DLLs, policies that disable admin tools, dead PATH entries, orphaned uninstall entries, hosts file entries |
| Security settings | Antivirus and Defender state, more than one antivirus, firewall, UAC, SMBv1, SMB signing on DCs, RDP without NLA, WDigest, LM/NTLMv1, old TLS, Guest account, local admins, BitLocker, Secure Boot and the 2023 certificate update, PowerShell 2.0, broad share permissions, expiring certificates |
| Network | Third-party time tools alongside Windows Time, domain machines using public DNS, APIPA addresses, internet name resolution, broken domain trust, time sync, WinHTTP proxy, NIC errors |
| Programs | End-of-life software (Flash, old Office, Java, QuickTime and so on), adware and "optimisers", OEM bloatware, vulnerable 7-Zip/WinRAR versions, duplicate versions, built-in Store apps people usually remove, consumer apps on servers, remote access tools on servers |
| Program logs | Error-level lines in recent logs under ProgramData and Program Files, grouped per application (warnings and telemetry noise ignored); DNS/connection failures reported by several applications grouped into one network finding; corruption logged in CBS.log |

### Server roles (checked automatically when found)

| Role | Checks |
|---|---|
| IIS | Stopped app pools and sites, 5xx error rates per site, WSUS app pool memory limit |
| SQL Server | End of support, high-severity ERRORLOG errors, failed logins, max server memory, databases that aren't online, missing full or log backups, auto-shrink |
| Active Directory | Replication failures (repadmin), dcdiag failures, SYSVOL still on FRS, PDC time source, AD Recycle Bin, Print Spooler running on DCs |
| DNS Server | Forwarders that don't respond, scavenging |
| DHCP Server | Scopes nearly full, inactive scopes |
| Hyper-V | Unhealthy VMs, old checkpoints, Replica health, VMs that are hard powered off when the host shuts down, VMQ enabled on 1 GbE switch adapters; memory judged after subtracting RAM assigned to VMs |
| Exchange | End of support, backed-up mail queues |

## Notes

- Run it from an elevated PowerShell. If it isn't elevated, Painfree stops and says so.
- A full scan usually takes 1 to 5 minutes. Domain controllers take longer because dcdiag runs; use `-Quick` to skip it.
- Health score: it starts at 100 and loses 15 points per Critical, 7 per High, 3 per Medium and 1 per Low finding.
- Commands in the report are examples. Replace anything in `<angle brackets>`, and back up or create a restore point before you change anything.
