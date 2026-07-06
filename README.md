# 🛡️ Threat Hunt Report // Northpeak Descent

### Community Hunt // An Operator Held the Front Door Open While Everyone Watched the Noise

---

## 📌 Executive Summary

*Pre-hunt framing (to be finalized post-hunt):*

Northpeak Logistics experienced a cross-platform intrusion on the evening of 16 June 2026. Multiple footholds gave an operator parallel access, external remote access into the Windows infrastructure alongside work from a Linux host used for reconnaissance and tooling. Between roughly 20:00 and 00:30 UTC the operator moved across the estate, staged tooling, set persistence, beaconed outbound, and reached the target data.

The environment surfaced a loud brute-force signal that reads as the entry point. It is not. The real entry authenticated clean and never tripped an alert.

---

## 🗂️ Environment

**Organization:** Northpeak Logistics
**Platform:** Windows estate + Linux host
**Telemetry:** Microsoft Sentinel // MDE tables (DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents)
**Scope:** Estate-wide, filtered to Northpeak hosts (npt-ws01, npt-srv01, npt-linux01)
**Window:** Evening of 16 June 2026

---

## 🎯 Hunt Stages

*[ gate + 5 phases, 18 flags total ]*

| Stage | Focus |
|---|---|
| 00 | Setup gate |
| 01 | Initial access |
| 02 | Linux recon & tooling |
| 03 | Pivot, execution, persistence |
| 04 | Command & control |
| 05 | Impact & judgement |

---

## 🚩 Flag-by-Flag Findings

### Stage 01 — Initial Access

**Flag 1: The Real Foothold**

HUNT LEAD: "They didn't exploit anything to get in. One external address got onto the Windows estate cleanly and worked it interactively. Give me that source and how they came through."

[Flag 1]

```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive","RemoteInteractive")
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
```

148.64.103.173, RDP


**Flag 2: First Foothold, Ordering**

HUNT LEAD: "There's more than one foothold here, and the obvious story has the Linux box first. Don't take that on trust. Prove which one actually came first, and name it."

[Flag 2]

```kql
DeviceLogonEvents
| where DeviceName == "npt-linux01"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
| order by Timestamp asc
```

npt-ws01, 148.64.103.173

**Flag 3: Operator Workstation Name**

[Flag 3]

```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where RemoteIP == "148.64.103.173"
| project RemoteDeviceName
```

loranse


**Flag 4: SRV01 Access Vector**

HUNT LEAD: "The server took its own way in, it wasn't reached from inside. Reconstruct it: the method, the source, the session type."

[Flag 4]

```kql
DeviceLogonEvents
| where DeviceName == "npt-srv01"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
| order by Timestamp asc
```

RDP, 148.64.103.173, RemoteInteractive


### Stage 02 — Linux Recon & Tooling


**Flag 5: Sudo Enumeration**

HUNT LEAD: "First thing on the Linux box, they checked what they could escalate with. Give me the exact command. They fumbled it once before they got it right, that's how you'll spot the real one."

[Flag 5]

```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

Upon investigating what the Linux box's command line history, I attempted to pinpoint the exact command that allowed the attacker to investigate. The hunt lead alerted me that they may have incorrectly typed the command before successfully running it through. Linux systems typically grant escalated privileges through the command 'sudo' so I queried for commands involving 'sudo' to detect the first indication of escalated privileges, which occurred at 2026-06-16T22:16:52.687226Z.

sudo -l

**Flag 6: Reachability Technique**

HUNT LEAD: "They checked whether the Windows boxes were reachable before they pivoted, and they did it without dropping a single tool on the box. Tell me how they checked, and the one port they cared about. That port tells you what they were about to do."

[Flag 6]

```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

During the investigation, it was clear they checked to identify which Windows box was reachable before pivoting, without the use of a tool. The attacker seemed to use the '/dev/tcp' command, which in Linux opens up bash and opens a network connection with the TCP protocol, and they targeted port 3389, which is Microsoft's Remote Desktop Protocol.

/dev/tcp, 3389 

**Flag 7: Operator Tooling**

HUNT LEAD: "Before leaving Linux, they kitted out, checked for a couple of capabilities, then committed to installing one tool. Name what they installed."

[Flag 7]

```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

I noticed around 2026-06-16T22:29:11.200233Z, they downloaded pipx onto the machine, which is a Python packaging tool to download something. Upon further investigation, it seems the tool downloaded after installing pipx was 'netexec'. Netexec is a tool that helps automate assessing the security of large networks.

netexec

### Stage 03 — Pivot, Execution, Persistence

**Flag 8: Lateral Movement Triple**

HUNT LEAD: "Now they come back at the workstation from inside the network. Build me that hop: the account, the internal source, the target."

[Flag 8]

```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01")
| where ActionType contains "success"
| project Timestamp, AccountName, RemoteIP, DeviceName
```

I needed confirmation after the installation of netexec that the attacker hopped back on the workstation from inside the network. Netexec was downloaded around 10:29 PM, so I looked for logins on the workstation after that time, with a successful logon so  I could capture the account, internal source, and target. I successfully found the account name, the internal source, which is most likely the Linux device IP, and the target, which was the Windows workstation.

sancadmin, 10.2.0.30, npt-ws01

**Flag 9: Operator PowerShell Lineage**

HUNT LEAD: "That workstation is drowning in PowerShell and nearly all of it is the machine talking to itself. Separate the human at the keyboard from the noise, and tell me what gives them away."

[Flag 9]

```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where FileName == "powershell.exe"
| summarize count() by InitiatingProcessFileName, InitiatingProcessAccountName
| order by count_ desc
```
After running the query above, I noticed several processes began running. To begin the separation of a human at the keyboard from noise, I needed to first separate what was done by the system and what was done by the user. I narrowed it down to processes between PowerShell and Explorer. This was a bit difficult to reason through, but after thinking it through, PowerShell could have been run by scripts, while Explorer will always need someone to click it from the keyboard.

explorer.exe

**Flag 10: Persistence Full Command**

HUNT LEAD: "They tried their staging script out a few times first, then trusted it enough to make it survive a reboot. Give me the full command they planted to bring it back, path and all."

[Flag 10]

```kql
DeviceRegistryEvents
| where DeviceName == "npt-ws01"
| where RegistryKey has_any ("Run", "RunOnce")
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```

I originally began searching for evidence of persistence within the DeviceProcessEvents logs, but I unsuccesfully located any logs containing evidence. From there, I checked the DeviceRegistryEvents to see if any keys were created, and I discovered a PowerShell script that was put into ProgramData instead of a user profile, which would allow it to survive regardless of the account it's tied to. 

powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"

**Flag 18:**

HUNT LEAD: "When the operator comes back into the workstation for the second time, before they touch anything else they run a short burst to check who they are and what they can do. The last command in that burst isn't a plain identity check, it's testing for one specific thing. Tell me what they were confirming about their own account."

[Flag 18]

```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where AccountName == "sancadmin"
| where FileName == "whoami.exe"
```

```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where AccountName == "sancadmin"
| project Timestamp, ProcessCommandLine, AdditionalFields
```

I used the first query to search the timestamps the attacker attempted to identify the user and what group they were a part of. This occurred at 10:41 PM. From there, I went to the commands put in place after that to further research and discovered that they also confirmed the SID, which is the Security Identifier used in Windows, and used the SID S-1-5-32-544, which is a well-known SID for the local admin group.

findstr /i S-1-5-32-544, confirms local administrator group membership


### Stage 04 — Command & Control


**Flag 11:Beacon Domains, Cross-Source**

[Flag 11]

```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ProcessCommandLine has "sync-northpeak"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

Attacker's C2 channel ran across three look-alike subdomains impersonating Northpeak's own infrastructure: status.sync-northpeak.com (first contact 11:15:47 PM, npt-ws01), updates.sync-northpeak.com (11:15:49 PM, npt-ws01), and cdn.sync-northpeak.com (11:44:08 PM, npt-srv01). All three were reached via PowerShell Invoke-WebRequest rather than a native network client.

status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; hidden in DeviceProcessEvents (PowerShell Invoke-WebRequest), not DeviceNetworkEvents

**Flag 12: Encoded Beacon Decode**

[Flag 12]

```kql


**Flag 13:**

### Stage 05 — Impact & Judgement

**Flag 15:**
**Flag 16:**
**Flag 17:**
**Flag 18:**

*(Each flag: screenshot, KQL used, finding.)*

---

## 🕒 Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| | | |

---

## 🧭 MITRE ATT&CK Mapping

| Flag | Tactic | Technique |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 10 | | |
| 11 | | |
| 12 | | |
| 13 | | |
| 14 | | |
| 15 | | |
| 16 | | |
| 17 | | |
| 18 | | |

---

## 🔑 Indicators of Compromise

| Type | Value |
|---|---|
| | |

---

## ⚖️ Judgement & Response

**Attack chain:** Entry → Pivot → Persistence → C2 → Impact

**What really happened:**

**How it was hidden:**

**Response actions (NIST SP 800-61):**
