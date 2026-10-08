# Lab Setup

## Architecture

```
Kali (attacker)  ──attack──►  Windows victim  ──logs──►  Splunk (SIEM)  ──►  detection fires
 192.168.56.30                 192.168.56.20              192.168.56.10
```

The victim records its own activity (Sysmon, Windows Security log, PowerShell log); the Universal Forwarder ships those logs to Splunk; I write detections there and investigate.

| Machine | Role | IP |
|---|---|---|
| splunk-server (Ubuntu Server 22.04) | SIEM | 192.168.56.10 |
| win10-victim (Windows 10 Pro 22H2) | Victim | 192.168.56.20 |
| kali | Attacker | 192.168.56.30 |

**Why logs go to a separate server:** an attacker who controls a machine can delete its local logs. Shipping logs off to a server the attacker can't reach keeps the evidence trustworthy — and in the real world you can't investigate hundreds of machines one by one, so logs are centralised.

**Why Splunk runs on Linux:** Splunk's system requirements list Windows 10 only for the Universal Forwarder, not for Splunk Enterprise. Ubuntu 22.04 is supported.

## Splunk server (Ubuntu)

- **Ubuntu Server, no desktop** — saves RAM for Splunk; real servers run headless. Managed over SSH.
- **Splunk Enterprise 10.4.3**, running as a dedicated `splunk` user that owns `/opt/splunk` (least privilege — a flaw in Splunk doesn't compromise the whole server).
- **60-day Enterprise Trial** — the Free licence disables alerting, which this project needs.
- **Receiving port 9997** enabled for the forwarder; **web UI on 8000**.

## Windows victim

- **Windows 10 Pro** (not Home) — Home can't accept incoming RDP (needed for Detection 1) and has no Group Policy Editor (needed to enable logging).
- **Host-only adapter only** by default; a NAT adapter was added temporarily for installs and removed before any attack.
- **Local admin account `user02`.**
- **Sysmon** with Olaf Hartong's sysmon-modular config (Balanced profile) — covers process creation, network, and more, for Detections 2–4.
- **Windows audit policy:** Logon success/failure (4625/4624) and *Other Object Access Events* (4698, off by default on workstations).
- **PowerShell Script Block Logging** enabled via Group Policy (4104) — off by default; it's what defeats encoded-command obfuscation in Detection 2.

## The telemetry pipeline

The Universal Forwarder on the victim ships three logs, all into one `windows` index:

| Log source (`source=`) | Carries |
|---|---|
| `WinEventLog:Security` | Logons (4625/4624), scheduled-task creation (4698) |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation (Event 1) and more |
| `WinEventLog:Microsoft-Windows-PowerShell/Operational` | Script Block Logging (4104) |

So every search starts with `index=windows`.

## Field extraction — the key setup decision

The forwarder's `inputs.conf` is set to **`renderXml = false`**. This is the single most important field-extraction fact in the project.

With XML rendering **on**, Splunk stored each Windows event as one blob of raw XML and did not break out the useful values — there was no `Account_Name` or `Source_Network_Address` to search on, so queries returned nothing. Normally Splunk would use the Splunkbase add-on for this, but I couldn't download it.

Turning XML rendering **off** makes events arrive as plain `key=value` text, and Splunk's built-in Windows parsing produces clean named fields automatically — **no add-on needed**. Confirmed fields in use: `EventCode`, `Account_Name`, `Source_Network_Address`, and the Sysmon fields `Image`, `OriginalFileName`, `ParentImage`, `CommandLine`, `IntegrityLevel`.

One exception: the scheduled-task definition in Event 4698 is still carried as XML inside the event, so Detection 3 extracts those fields in the query with `rex` and `spath`.

## Accepted risks

Acceptable only in an isolated lab: weak passwords, end-of-support Windows 10, Splunk below reference hardware, and Windows Defender disabled for Detection 4 (a deliberate AV-bypass stand-in — a real attacker on the host would evade AV too). Each would be handled differently in production.
