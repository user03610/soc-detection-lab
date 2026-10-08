# SOC Detection Lab

A home SOC lab where I simulate real attacks, detect them in Splunk, and deploy alerts that fire on their own. Each detection is behaviour-based, tuned for false positives, and mapped to both MITRE ATT&CK and the Saudi NCA ECC-2:2024 controls.

Built and tested entirely on isolated, owned systems, in line with the Saudi Anti-Cyber Crime Law.

## What this project shows

- Operating a SIEM end to end: building the pipeline, writing detection logic, investigating alerts.
- Detection engineering: every detection is a deployed, scheduled alert confirmed firing on a live attack.
- Behaviour-based rules that survive the attacker changing their IP, filename, URL, or payload.
- False-positive analysis and tuning.
- Event correlation across multiple log sources.
- Triage/response steps and a GRC control mapping for each detection.

## The lab

An isolated host-only network (`192.168.56.0/24`) in VirtualBox.

| Machine | Role | IP |
|---|---|---|
| splunk-server (Ubuntu 22.04 + Splunk Enterprise) | SIEM — collects and searches logs | 192.168.56.10 |
| win10-victim (Windows 10 Pro) | Victim — Sysmon + Universal Forwarder | 192.168.56.20 |
| kali | Attacker | 192.168.56.30 |

**Logging:** Sysmon (Olaf Hartong's sysmon-modular config), Windows Security auditing, and PowerShell Script Block Logging, all shipped to Splunk by the Universal Forwarder into one `windows` index. Full build is in [lab-setup.md](lab-setup.md).

## The detections

| # | Detection | MITRE ATT&CK | Attack stage | Log source | Severity |
|---|---|---|---|---|---|
| 1 | [RDP Brute Force](detections/01-rdp-brute-force.md) | T1110 | Credential Access | Security 4625 / 4624 | High |
| 2 | [Obfuscated PowerShell](detections/02-obfuscated-powershell-T1059.001.md) | T1059.001 | Execution | Sysmon 1 + PowerShell 4104 | Medium |
| 3 | [Scheduled Task Persistence](detections/03-scheduled-task-persistence-T1053_005.md) | T1053.005 | Persistence | Security 4698 + Sysmon 1 | High |
| 4 | [SAM Hive Dump](detections/04-sam-hive-dump-T1003_002.md) | T1003.002 | Credential Access | Sysmon 1 | High |

The four span distinct stages of an intrusion — getting in, running code, staying in, and stealing credentials.

## Each detection write-up covers

The attack and how it was run · the log source and specific Event IDs · the SPL query (behaviour-based) · event volume · false-positive analysis and tuning · triage/response steps · the ATT&CK technique · screenshots of the attack and the alert firing · the NCA ECC-2:2024 control mapping.

## Repo structure

```
soc-detection-lab/
├── README.md
├── lab-setup.md          architecture and build decisions
├── detections/           one write-up per detection
├── spl/                  the raw SPL queries
└── screenshots/          evidence
```

## A note on field extraction

The forwarder sends Windows events as plain text (`renderXml = false`), which makes Splunk's built-in Windows parsing produce clean named fields with no Splunkbase add-on required. Where a field still lives inside event XML (the scheduled-task definition in Event 4698), the query extracts it with `rex` and `spath`.
