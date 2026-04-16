# Attack Disruption & Endpoint Logon Forensics

**Created:** 2026-04-16  
**Platform:** Microsoft Defender XDR  
**Tables:** DisruptionAndResponseEvents, DeviceLogonEvents, AlertInfo, AlertEvidence  
**Keywords:** attack disruption, containment, user containment, SMB block, RDP block, logon block, IP containment, lateral movement, NTLM, Kerberos, pass-the-hash, SafeBootGuard, pre-containment, post-containment, disruption effectiveness  
**MITRE:** T1021.001, T1021.002, T1110.001, T1110.003, T1550.002, T1078.002, TA0008, TA0006  
**Domains:** endpoint, identity  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This file covers two complementary telemetry surfaces for endpoint security operations:

**Part A — Attack Disruption (`DisruptionAndResponseEvents`):** Defender XDR's automated attack disruption actions — user containment, IP blocks, SMB/RDP/RPC service blocks, and SafeBootGuard policy deployments. These events record what Defender *did* to stop an attack in progress.

**Part B — Endpoint Logon Forensics (`DeviceLogonEvents`):** Protocol-level logon analysis (Kerberos vs NTLM), lateral movement patterns, and pre/post-containment behavioral correlation. These queries answer whether containment was effective and what the attacker was doing.

**Part C — Alert Correlation:** Joins disruption events with `AlertInfo`/`AlertEvidence` to map containment actions to the alerts and attack techniques that triggered them.

**⚠️ Table Pitfalls**

| Pitfall | Detail |
|---------|--------|
| `DisruptionAndResponseEvents` is **AH-only** | Not available in Sentinel Data Lake. Use `RunAdvancedHuntingQuery` only |
| `ReportId` is `long` not `string` | Unlike most MDE tables where ReportId is string, here it's `long` |
| `SourceUserName` can be empty | IP containment events (`ContainedIpBlocked`) have no user context — only `SourceIpAddress` |
| `IsPolicyOn` is `bool` in schema but returns as `int` | Use `IsPolicyOn == true` or `IsPolicyOn == 1` for filtering |
| `DeviceName` vs `TargetDeviceName` | `DeviceName` is the device reporting the event; `TargetDeviceName` is the device the contained user was trying to reach. For SMB/logon blocks, the target is the interesting one |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Disruption Event Summary — Action Type Breakdown](#query-1-disruption-event-summary--action-type-breakdown) | Dashboard | `DisruptionAndResponseEvents` |
| 2 | [Contained User Profile — Per-Actor Disruption Summary](#query-2-contained-user-profile--per-actor-disruption-summary) | Dashboard | `DisruptionAndResponseEvents` |
| 3 | [Containment Event Detail — Full Forensic Timeline](#query-3-containment-event-detail--full-forensic-timeline) | Investigation | `DisruptionAndResponseEvents` |
| 4 | [Disruption Timeline — Daily Trend by Service](#query-4-disruption-timeline--daily-trend-by-service) | Dashboard | `DisruptionAndResponseEvents` |
| 5 | [SafeBootGuard Policy Coverage](#query-5-safebootguard-policy-coverage) | Investigation | `DisruptionAndResponseEvents` |
| 6 | [Contained User → Alert Correlation](#query-6-contained-user--alert-correlation) | Detection | `AlertInfo` + `DisruptionAndResponseEvents` |
| 7 | [Disruption Effectiveness — Pre vs Post Containment Behavior](#query-7-disruption-effectiveness--pre-vs-post-containment-behavior) | Investigation | `DeviceLogonEvents` + `DisruptionAndResponseEvents` |
| 8 | [Pre-Containment Activity Forensics](#query-8-pre-containment-activity-forensics) | Investigation | `DeviceLogonEvents` + `DisruptionAndResponseEvents` |
| 9 | [Endpoint Logon Protocol Baseline — Kerberos vs NTLM](#query-9-endpoint-logon-protocol-baseline--kerberos-vs-ntlm) | Dashboard | `DeviceLogonEvents` |
| 10 | [NTLM Brute Force Detection — Failed Network Logons by Source](#query-10-ntlm-brute-force-detection--failed-network-logons-by-source) | Detection | `DeviceLogonEvents` |
| 11 | [RDP Session Inventory — Remote Interactive Logons](#query-11-rdp-session-inventory--remote-interactive-logons) | Posture | `DeviceLogonEvents` |


## Queries

### Query 1: Disruption Event Summary — Action Type Breakdown

**Purpose:** Executive overview of all attack disruption actions over the reporting period. Shows which containment mechanisms fired, how many devices and users were affected, and the distribution across services (SMB, RDP, RPC).  
**Severity:** Informational  
**MITRE:** TA0008  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical summary with dcount — not suitable for CD row-level output"
-->

```kql
DisruptionAndResponseEvents
| where Timestamp > ago(30d)
| summarize 
    Count = count(),
    Devices = dcount(DeviceName),
    Users = dcount(SourceUserName),
    SourceIPs = dcount(SourceIpAddress)
    by ActionType, ReportType, DataSource, Service
| sort by Count desc
```

**Expected results:** One row per ActionType showing containment mechanism distribution. Common ActionTypes: `ContainedUserSmbFileOpenBlocked`, `ContainedIpBlocked`, `ContainedUserLogonBlocked`, `ContainedUserRpcAccessBlocked`, `ContainedUserRemoteDesktopSessionDisconnected`, `SafeBootGuardPolicyApplied`.

---

### Query 2: Contained User Profile — Per-Actor Disruption Summary

**Purpose:** Identify who was contained and what containment actions were applied. Shows per-user/IP breakdown of SMB blocks, logon blocks, IP blocks, RDP blocks, and RPC blocks with target device enumeration.  
**Severity:** High  
**MITRE:** T1021.002, T1550.002, TA0008  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query per contained entity — use Q3 for CD-ready per-event detection"
-->

```kql
DisruptionAndResponseEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Contained"
| summarize 
    TotalActions = count(),
    SMBBlocks = countif(ActionType == "ContainedUserSmbFileOpenBlocked"),
    LogonBlocks = countif(ActionType == "ContainedUserLogonBlocked"),
    IPBlocks = countif(ActionType == "ContainedIpBlocked"),
    RDPBlocks = countif(ActionType has "RemoteDesktop"),
    RPCBlocks = countif(ActionType == "ContainedUserRpcAccessBlocked"),
    TargetDevices = make_set(DeviceName, 10),
    Services = make_set(Service, 5),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by SourceUserName, SourceUserDomainName, SourceIpAddress
| sort by TotalActions desc
```

**Expected results:** One row per contained entity (user or IP). Entities with high `TotalActions` and diverse block types (SMB + logon + RDP) indicate active lateral movement that was disrupted across multiple vectors.

---

### Query 3: Containment Event Detail — Full Forensic Timeline

**Purpose:** Raw event-level detail for all containment actions. Use for incident timeline reconstruction and understanding exactly what was blocked, when, and on which device.  
**Severity:** High  
**MITRE:** T1021.002, T1021.001, TA0008  

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
title: "Attack Disruption: {{ActionType}} — {{SourceUserName}} blocked on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Investigate the contained user/IP. Check AlertInfo for the triggering alert. Verify containment is still active and assess whether the user account needs credential reset."
adaptation_notes: "Already row-level with project. Add DeviceId for CD mandatory columns."
-->

```kql
DisruptionAndResponseEvents
| where Timestamp > ago(1h)
| where ActionType startswith "Contained"
| project Timestamp, ActionType, ReportType, Service,
    SourceUserName, SourceUserDomainName, SourceIpAddress,
    DeviceName, TargetDeviceName, 
    ShareName, FileName, LogonType,
    InitiatingProcessFileName,
    DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** Each row is a single containment action. Key fields: `ActionType` (what was blocked), `Service` (SMB/RDP/RPC), `SourceUserName` (the contained user), `DeviceName` (where the block was enforced), `ShareName`/`FileName` (for SMB blocks — what file access was denied).

---

### Query 4: Disruption Timeline — Daily Trend by Service

**Purpose:** Visualize containment activity over time. Spikes indicate active attack campaigns. Sustained activity may indicate incomplete containment or persistent attacker.  
**Severity:** Informational  
**MITRE:** TA0008  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Time-series aggregation dashboard — not suitable for CD"
-->

```kql
DisruptionAndResponseEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Contained"
| summarize 
    TotalActions = count(),
    SMB = countif(Service == "SMB"),
    RDP = countif(ActionType has "RemoteDesktop"),
    RPC = countif(Service == "RPC"),
    LogonBlocks = countif(ActionType == "ContainedUserLogonBlocked"),
    IPBlocks = countif(ActionType == "ContainedIpBlocked"),
    UniqueUsers = dcount(SourceUserName),
    UniqueDevices = dcount(DeviceName)
    by bin(Timestamp, 1d)
| sort by Timestamp asc
```

**Expected results:** Daily counts by service type. Look for concentrated spikes (active incident response) vs sustained low-volume blocks (persistent attacker or ongoing simulation).

---

### Query 5: SafeBootGuard Policy Coverage

**Purpose:** Audit SafeBootGuard policy deployment across the fleet. SafeBootGuard prevents attackers from booting devices into Safe Mode to disable Defender. Shows how many devices have the policy on vs off.  
**Severity:** Medium  
**MITRE:** T1562.001  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Posture/inventory query — requires aggregation"
-->

```kql
DisruptionAndResponseEvents
| where Timestamp > ago(30d)
| where ActionType == "SafeBootGuardPolicyApplied"
| summarize arg_max(Timestamp, *) by DeviceName
| summarize 
    PolicyOn = countif(IsPolicyOn == true),
    PolicyOff = countif(IsPolicyOn == false),
    TotalDevices = dcount(DeviceName)
| extend CoverageRate = round(todouble(PolicyOn) / (PolicyOn + PolicyOff) * 100, 1)
```

**Expected results:** Single row showing fleet-wide SafeBootGuard coverage. `CoverageRate` < 100% means some devices can be booted into Safe Mode to disable endpoint protection.

**Tuning:** To identify specific uncovered devices: remove the outer `summarize` and add `| where IsPolicyOn == false | project DeviceName, Timestamp`.

---

### Query 6: Contained User → Alert Correlation

**Purpose:** Map contained users to the alerts and attack techniques that triggered their containment. Answers "why was this user contained?" with specific alert titles, severities, MITRE techniques, and attack categories.  
**Severity:** High  
**MITRE:** T1021.002, T1550.002, T1003, TA0008, TA0006  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table join with dcount aggregation — not CD-compatible"
-->

```kql
let DisruptedUsers = DisruptionAndResponseEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Contained"
| where isnotempty(SourceUserName)
| distinct SourceUserName;
AlertEvidence
| where Timestamp > ago(30d)
| where EntityType == "User"
| join kind=inner DisruptedUsers on $left.AccountName == $right.SourceUserName
| distinct AlertId, AccountName
| join kind=inner (
    AlertInfo
    | where Timestamp > ago(30d)
) on AlertId
| summarize 
    AlertCount = dcount(AlertId),
    Titles = make_set(Title, 10),
    Severities = make_set(Severity),
    Categories = make_set(Category),
    Techniques = make_set(AttackTechniques, 10)
    by AccountName
| sort by AlertCount desc
```

**Expected results:** One row per contained user with their full alert portfolio. High-severity alerts with LateralMovement/CredentialAccess categories confirm containment was justified. Look for `Pass the Hash`, `Kekeo`, `Credential Dumping`, `SMB lateral movement` in titles.

---

### Query 7: Disruption Effectiveness — Pre vs Post Containment Behavior

**Purpose:** Compare a contained user's logon activity before and after their first containment event. Measures whether containment actually stopped the lateral movement or the attacker adapted.  
**Severity:** High  
**MITRE:** T1078.002, T1550.002, TA0008  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical comparison query with let blocks and Phase pivot — not CD-compatible"
-->

```kql
let ContainedUsers = DisruptionAndResponseEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Contained"
| where isnotempty(SourceUserName)
| summarize FirstContainment = min(Timestamp), LastContainment = max(Timestamp) by SourceUserName;
DeviceLogonEvents
| where Timestamp > ago(30d)
| join kind=inner ContainedUsers on $left.AccountName == $right.SourceUserName
| extend Phase = iff(Timestamp < FirstContainment, "Pre-Containment", "Post-Containment")
| summarize 
    LogonAttempts = count(),
    Successes = countif(ActionType == "LogonSuccess"),
    Failures = countif(ActionType == "LogonFailed"),
    UniqueDevices = dcount(DeviceName),
    Protocols = make_set(Protocol)
    by AccountName, Phase
| sort by AccountName, Phase
```

**Expected results:** Two rows per contained user (Pre/Post). Effective containment shows: (1) Post-containment failures increase, (2) Post-containment device reach decreases, (3) Post-containment successful logons drop. If post-containment successes remain high or increase, the containment may have been bypassed or the account was re-compromised.

---

### Query 8: Pre-Containment Activity Forensics

**Purpose:** Reconstruct what a contained user was doing in the period leading up to their first containment action. Shows logon patterns, target devices, protocols, and source IPs to understand the attack chain.  
**Severity:** High  
**MITRE:** T1021.002, T1078.002, TA0008  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation query with let block and temporal join — not CD-compatible"
-->

```kql
let ContainedUsers = DisruptionAndResponseEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Contained"
| where isnotempty(SourceUserName)
| summarize FirstContainment = min(Timestamp) by SourceUserName;
DeviceLogonEvents
| where Timestamp > ago(30d)
| join kind=inner ContainedUsers on $left.AccountName == $right.SourceUserName
| where Timestamp between (ago(30d) .. FirstContainment)
| summarize 
    PreDisruptionLogons = count(),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    FailedLogons = countif(ActionType == "LogonFailed"),
    Protocols = make_set(Protocol),
    LogonTypes = make_set(LogonType),
    TargetDevices = make_set(DeviceName, 10),
    SourceIPs = make_set(RemoteIP, 5)
    by AccountName, FirstContainment
| sort by PreDisruptionLogons desc
```

**Expected results:** One row per contained user showing their pre-containment attack footprint. Look for: NTLM protocol usage (pass-the-hash), multiple target devices (lateral spread), RemoteInteractive logon type (RDP sessions), and high failure counts (credential spraying).

---

### Query 9: Endpoint Logon Protocol Baseline — Kerberos vs NTLM

**Purpose:** Map the Kerberos vs NTLM ratio per device for network logons. High NTLM ratios on domain-joined devices may indicate pass-the-hash activity, legacy authentication, or misconfigured services.  
**Severity:** Medium  
**MITRE:** T1550.002, TA0008  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical baseline per device — not suitable for CD"
-->

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "Network" and ActionType == "LogonSuccess"
| summarize 
    KerberosCount = countif(Protocol == "Kerberos"),
    NTLMCount = countif(Protocol == "NTLM"),
    OtherCount = countif(Protocol !in ("Kerberos", "NTLM")),
    UniqueUsers = dcount(AccountName),
    UniqueSourceIPs = dcount(RemoteIP)
    by DeviceName
| extend NTLMRatio = round(todouble(NTLMCount) / (KerberosCount + NTLMCount + OtherCount) * 100, 1)
| where KerberosCount + NTLMCount > 0
| sort by NTLMRatio desc
```

**Expected results:** Devices ranked by NTLM dependency. Domain controllers should show low NTLM ratios (Kerberos-dominant). Workstations with >50% NTLM for network logons warrant investigation — may indicate pass-the-hash, legacy apps, or cross-forest trusts without Kerberos.

---

### Query 10: NTLM Brute Force Detection — Failed Network Logons by Source

**Purpose:** Identify sources performing NTLM brute force or password spray attacks against endpoints. Groups failed NTLM network logons by source IP to find attackers.  
**Severity:** High  
**MITRE:** T1110.001, T1110.003, TA0006  

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "NTLM Brute Force: {{RemoteIP}} — {{FailedAttempts}} failures against {{UniqueTargetUsers}} users"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Investigate the source IP. Check if it's a known internal device or an external attacker. Review the target user list for high-value accounts. Consider blocking the IP and resetting affected credentials."
adaptation_notes: "Refactor let blocks. Convert summarize to row-level with threshold filter."
-->

```kql
DeviceLogonEvents
| where Timestamp > ago(1h)
| where Protocol == "NTLM" and ActionType == "LogonFailed" and LogonType == "Network"
| summarize 
    FailedAttempts = count(),
    UniqueTargetUsers = dcount(AccountName),
    TargetUsers = make_set(AccountName, 10),
    TargetDevices = make_set(DeviceName, 10),
    FirstAttempt = min(Timestamp),
    LastAttempt = max(Timestamp)
    by RemoteIP
| where FailedAttempts >= 10
| sort by FailedAttempts desc
```

**Expected results:** Source IPs with 10+ NTLM failures. Sources targeting many unique users suggest password spray. Sources targeting one user suggest brute force. Cross-reference with `DisruptionAndResponseEvents` to check if containment was triggered.

**Tuning:** Raise `FailedAttempts >= 10` threshold in environments with legacy NTLM apps. Add `| where UniqueTargetUsers >= 3` to focus on spray patterns.

---

### Query 11: RDP Session Inventory — Remote Interactive Logons

**Purpose:** Enumerate all RDP (Remote Interactive) sessions across the fleet. Identifies which users are RDP-ing into which devices and from where.  
**Severity:** Medium  
**MITRE:** T1021.001, TA0008  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation inventory — use for baseline, not alerting"
-->

```kql
DeviceLogonEvents
| where Timestamp > ago(30d)
| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
| summarize 
    SessionCount = count(),
    FirstSession = min(Timestamp),
    LastSession = max(Timestamp),
    SourceIPs = make_set(RemoteIP, 5)
    by DeviceName, AccountName, AccountDomain
| sort by SessionCount desc
```

**Expected results:** User-to-device RDP session map. Unusual patterns: admin accounts RDP-ing to workstations, service accounts with interactive RDP, sessions from external IPs (non-10.x/192.168.x). Cross-reference with disruption events — RDP sessions to contained devices may indicate attacker persistence.

---

## References

- [Attack disruption in Microsoft Defender XDR — Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption)
- [DisruptionAndResponseEvents table — Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-disruptionandresponseevents-table)
- [DeviceLogonEvents table — Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
