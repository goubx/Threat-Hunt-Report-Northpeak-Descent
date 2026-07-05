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

```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive","RemoteInteractive")
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
```

148.64.103.173, RDP

[Flag 1]

**Flag 2: First Foothold, Ordering**

HUNT LEAD: "There's more than one foothold here, and the obvious story has the Linux box first. Don't take that on trust. Prove which one actually came first, and name it."

```kql
DeviceLogonEvents
| where DeviceName == "npt-linux01"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
| order by Timestamp asc
```

[Flag 2]

npt-ws01, 148.64.103.173

**Flag 3: Operator Workstation Name**

```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where RemoteIP == "148.64.103.173"
| project RemoteDeviceName
```

[Flag 3}

loranse

### Stage 02 — Linux Recon & Tooling

**Flag 4:**
**Flag 5:**
**Flag 6:**

### Stage 03 — Pivot, Execution, Persistence

**Flag 7:**
**Flag 8:**
**Flag 9:**
**Flag 10:**

### Stage 04 — Command & Control

**Flag 11:**
**Flag 12:**
**Flag 13:**
**Flag 14:**

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
