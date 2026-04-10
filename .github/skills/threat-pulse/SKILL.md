---
name: threat-pulse
description: 'Recommended starting point for new users and daily SOC operations. Quick 15-minute security posture scan across 9 domains: active incidents, identity anomalies, risky sign-ins, device process drift, rare process chains, critical asset exposure, SPN behavioral drift, email threats, UEBA behavioral signals, mailbox rule manipulation, privileged operations, and exploitable CVEs. Produces a prioritized Threat Pulse Dashboard with color-coded verdicts and drill-down recommendations pointing to specialized skills. Trigger on getting-started questions like "what can you do", "where do I start", "help me investigate". Supports inline chat and markdown file output'
---

# Threat Pulse — Instructions

## Purpose

The Threat Pulse skill is a rapid, broad-spectrum security scan designed for the "if you only had 15 minutes" scenario. It executes 12 high-level queries across 9 security domains in parallel, producing a prioritized dashboard of findings with drill-down recommendations to specialized investigation skills.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔴 **Incidents** | What high-severity incidents are open and unresolved? How old are they? Who owns them? |
| 🔐 **Identity Anomalies** | Which users have the most anomalous sign-in patterns this week? |
| 🔐 **Identity Protection** | How many risky sign-ins? Which users are atRisk or confirmedCompromised? |
| 💻 **Device Drift** | Which endpoints deviated most from their process behavioral baseline? |
| 💻 **Rare Processes** | What singleton process chains exist that warrant threat hunting? |
| 🛡️ **Critical Assets** | Are any critical assets internet-facing? Do they have RCE vulnerabilities? |
| 🤖 **SPN Drift** | Which service principals expanded their resource/IP/location footprint? |
| 📧 **Email Threats** | What's the phishing/spam/malware breakdown? Were any phishing emails delivered? |
| 📈 **UEBA Behaviors** | What sub-alert behavioral signals exist (impossible travel, mass download, credential manipulation)? |
| � **Auth Spray** | Are there password spray / brute-force patterns across Entra ID sign-ins and RDP/SSH endpoints? |
| 🔑 **Privileged Ops** | Who performed high-impact admin operations this week? |
| 🛡️ **Exploitable CVEs** | What exploitable CVEs (CVSS ≥ 8) are present across the fleet? |

**Data sources:** `SecurityIncident`, `SecurityAlert`, `Signinlogs_Anomalies_KQL_CL` (custom, fallback: `SigninLogs`), `SigninLogs`, `DeviceProcessEvents`, `DeviceLogonEvents`, `ExposureGraphNodes`, `AADServicePrincipalSignInLogs`, `EmailEvents`, `BehaviorInfo`, `BehaviorEntities`, `AuditLogs`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`

**References:**
- [Microsoft Sentinel — SecurityIncident](https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference#securityincident)
- [Microsoft Sentinel — SecurityAlert](https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference#securityalert)
- [Defender XDR — Advanced Hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Defender TVM — Software Vulnerabilities](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table)
- [Exposure Management — ExposureGraphNodes](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)

### 🔴 URL Registry — Canonical Links for Report Generation

**MANDATORY:** When generating reports, copy URLs **verbatim** from this registry. NEVER construct, guess, or paraphrase a URL.

| Label | Canonical URL |
|-------|---------------|
| `DOCS_SECURITY_INCIDENT` | `https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference#securityincident` |
| `DOCS_ADVANCED_HUNTING` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview` |
| `DOCS_IDENTITY_PROTECTION` | `https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection` |
| `DOCS_EXPOSURE_MANAGEMENT` | `https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph` |
| `DOCS_TVM` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table` |
| `DOCS_EMAIL_EVENTS` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table` |
| `DOCS_BEHAVIOR_ANALYTICS` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table` |
| `XDR_INCIDENT_BASE` | `https://security.microsoft.com/incidents/` |

**Usage in reports:** When referencing incidents, always construct portal links as `XDR_INCIDENT_BASE` + `ProviderIncidentId`. When referencing documentation, use the appropriate `DOCS_*` label.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** — Mandatory execution requirements
2. **[Execution Workflow](#execution-workflow)** — Phased query plan with parallel groups
3. **[Sample KQL Queries](#sample-kql-queries)** — All 12 verified queries with fallback logic
4. **[Post-Processing](#post-processing)** — Device drift score computation, cross-query correlation
5. **[Query File Recommendations](#query-file-recommendations)** — Dynamic hunting follow-up from findings
6. **[Output Modes](#output-modes)** — Inline, markdown file, or both
7. **[Inline Report Template](#inline-report-template)** — Dashboard format with verdicts
8. **[Markdown File Report Template](#markdown-file-report-template)** — Extended format with appendices
9. **[Known Pitfalls](#known-pitfalls)** — Table-specific gotchas
10. **[Quality Checklist](#quality-checklist)** — Pre-output validation
11. **[SVG Dashboard Generation](#svg-dashboard-generation)** — Optional visual dashboard

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Workspace selection** — Follow the SENTINEL WORKSPACE SELECTION rule from `copilot-instructions.md`. Call `list_sentinel_workspaces()` before first query.

2. **Read `config.json`** — Load workspace ID, tenant, subscription, and Azure MCP parameters before execution.

3. **ASK the user** for output preferences before executing queries:
   - **Output mode:** Inline chat / Markdown file / Both
   - **Lookback override:** Default is 7d for most queries; user may want 14d or 30d
   - If user says "just run it" or similar, default to **inline chat** with **7d lookback**.

4. **⛔ MANDATORY: Evidence-based analysis only** — Every finding must cite query results. Every "clear" verdict must cite 0 results. Follow the Evidence-Based Analysis rule from `copilot-instructions.md`.

5. **Parallel execution** — Run all Data Lake queries in parallel (Q1, Q2/Q2b, Q3, Q7, Q10, Q11). Run all Advanced Hunting queries in parallel (Q4, Q5, Q6, Q8, Q9, Q12). The two groups can overlap.

6. **Graceful fallback for Q2** — `Signinlogs_Anomalies_KQL_CL` is a custom table that may not exist in all workspaces. If query returns `SemanticError: Failed to resolve table`, immediately execute **Q2b** (Identity Protection fallback) instead. Do NOT report the custom table failure as an error — silently fall back and note the data source in the report.

7. **Cross-query correlation** — After all queries complete, check for correlated findings:
   - User appearing in **both** Q2/Q2b anomalies AND Q3 risky sign-ins → escalate priority
   - SPN drift (Q7) + unusual OAuth credential addition (Q9) → escalate priority
   - Device in rare process chains (Q5) + device in CVE list (Q12) → escalate priority
   - Incident entities (Q1) matching users in Q2/Q3 → link findings

8. **SecurityIncident output rule** — Every incident MUST include a clickable Defender XDR portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}`.

---

## Execution Workflow

### Phase 0: Prerequisites

1. Read `config.json` for workspace ID and Azure MCP parameters
2. Call `list_sentinel_workspaces()` to enumerate available workspaces
3. Ask user for output mode and lookback preference (or use defaults)

### Phase 1: Data Lake Queries (Q1, Q2, Q3, Q7, Q11)

**Run all 5 in parallel — no dependencies between queries.**

| Query | Domain | Purpose | Tool |
|-------|--------|---------|------|
| Q1 | 🔴 Incidents | Open High/Critical incidents with MITRE tactics | `query_lake` |
| Q2 | 🔐 Identity | Fleet-wide sign-in anomalies (High/Medium) | `query_lake` |
| Q3 | 🔐 Identity | Risky sign-ins / Identity Protection summary | `query_lake` |
| Q7 | 🤖 SPN | Service principal behavioral drift (90d vs 7d) | `query_lake` |
| Q11 | 🔑 Privilege | High-impact admin operations | `query_lake` |

**Fallback:** If Q2 fails with table resolution error, execute Q2b in its place.

### Phase 2: Advanced Hunting Queries (Q4, Q5, Q6, Q8, Q9, Q10, Q12)

**Run all 7 in parallel — no dependencies between queries.**

| Query | Domain | Purpose | Tool |
|-------|--------|---------|------|
| Q4 | 💻 Endpoint | Fleet device process drift (7d baseline vs 1d) | `RunAdvancedHuntingQuery` |
| Q5 | 💻 Endpoint | Rare process chain singletons (90d) | `RunAdvancedHuntingQuery` |
| Q6 | 🛡️ Exposure | Internet-facing critical assets | `RunAdvancedHuntingQuery` |
| Q8 | 📧 Email | Inbound email threat snapshot | `RunAdvancedHuntingQuery` |
| Q9 | 📈 UEBA | MCAS/UEBA behavioral detections | `RunAdvancedHuntingQuery` |
| Q10 | 🔐 Auth Spray | Password spray / brute-force across Entra ID + RDP/SSH | `RunAdvancedHuntingQuery` |
| Q12 | 🛡️ Vuln | Exploitable CVEs (CVSS ≥ 8) across fleet | `RunAdvancedHuntingQuery` |

### Phase 3: Post-Processing & Report

1. Interpret device drift scores from Q4 results (see [Post-Processing](#post-processing))
2. Run cross-query correlation checks (see rule 7 above)
3. Assign verdicts to each domain (🔴 Escalate / 🟠 Investigate / 🟡 Monitor / ✅ Clear)
4. Generate prioritized recommendations with drill-down skill references
5. Search for relevant query files (see [Query File Recommendations](#query-file-recommendations)) — only when 🔴/🟠 verdicts exist
6. Render output in requested mode

---

## Sample KQL Queries

> **All queries below are verified against live Sentinel/Defender XDR schemas. Use them exactly as written. Lookback periods use `ago(Nd)` — substitute the user's preferred lookback where noted.**

### Query 1: Open High-Severity Incidents with MITRE Techniques

🔴 **Incident hygiene** — Surfaces unresolved High/Critical incidents with age, owner, alert count, and MITRE tactics.

**Tool:** `mcp_sentinel-data_query_lake`

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active")
| where Severity in ("High", "Critical")
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project SystemAlertId, Tactics, AlertName, AlertSeverity
) on $left.AlertId == $right.SystemAlertId
| summarize 
    Tactics = make_set(Tactics),
    AlertNames = make_set(AlertName, 5),
    AlertCount = dcount(AlertId)
    by ProviderIncidentId, Title, Severity, Status, CreatedTime,
       OwnerUPN = tostring(Owner.userPrincipalName)
| extend AgeDays = datetime_diff('day', now(), CreatedTime)
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| order by Severity asc, AgeDays desc
| take 15
```

**Purpose:** Identifies the top 15 open high-severity incidents, ranked by age. Joins SecurityAlert for MITRE tactic visibility. Flags unassigned incidents (empty OwnerUPN) and incident age debt (>30 days old).

**Verdict logic:**
- 🔴 Escalate: Any incident with `AgeDays > 30` AND empty `OwnerUPN`
- 🟠 Investigate: Any incident with `AgeDays > 14` or `AlertCount > 10`
- 🟡 Monitor: Open incidents exist but are assigned and recently triaged
- ✅ Clear: 0 open High/Critical incidents

---

### Query 2: Fleet-Wide Sign-In Anomalies (Primary — Custom Table)

🔐 **Anomaly detection** — Queries the pre-computed `Signinlogs_Anomalies_KQL_CL` table for High/Medium anomalies across ALL users.

**Tool:** `mcp_sentinel-data_query_lake`

**⚠️ CUSTOM TABLE — may not exist in all workspaces. If `SemanticError: Failed to resolve table`, silently execute Q2b instead.**

```kql
Signinlogs_Anomalies_KQL_CL
| where TimeGenerated > ago(7d)
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10, "Medium",
    CountryNovelty or CityNovelty or StateNovelty, "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| where Severity in ("High", "Medium")
| summarize 
    AnomalyCount = count(),
    HighCount = countif(Severity == "High"),
    TopAnomalyTypes = make_set(AnomalyType, 5),
    TopCountries = make_set(Country, 5),
    LatestDetection = max(DetectedDateTime)
    by UserPrincipalName
| order by HighCount desc, AnomalyCount desc
| take 15
```

**Purpose:** Surfaces top 15 users with the most High/Medium sign-in anomalies in the past 7 days. Geographic novelty (new countries/cities) combined with high hit counts indicates potential account compromise or token theft.

---

### Query 2b: Fleet-Wide Sign-In Anomalies (Fallback — Identity Protection)

🔐 **Identity Protection fallback** — Used when `Signinlogs_Anomalies_KQL_CL` does not exist. Queries `SigninLogs` risk detections and `AADUserRiskEvents` for equivalent anomaly coverage.

**Tool:** `mcp_sentinel-data_query_lake`

**⚠️ EXECUTE ONLY if Q2 fails with table resolution error.**

```kql
let RiskySignins = SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium", "low") or RiskState in ("atRisk", "confirmedCompromised")
| where isnotempty(RiskEventTypes_V2)
| extend RiskEvents = parse_json(RiskEventTypes_V2)
| mv-expand RiskEvent = RiskEvents
| extend RiskEventType = tostring(RiskEvent)
| summarize
    AnomalyCount = count(),
    HighCount = countif(RiskLevelDuringSignIn == "high"),
    MediumCount = countif(RiskLevelDuringSignIn == "medium"),
    TopRiskEvents = make_set(RiskEventType, 5),
    TopCountries = make_set(Location, 5),
    TopIPs = make_set(IPAddress, 5),
    LatestDetection = max(TimeGenerated)
    by UserPrincipalName
| order by HighCount desc, AnomalyCount desc
| take 15;
RiskySignins
```

**Purpose:** Fallback that achieves similar anomaly coverage via Identity Protection risk detections (unfamiliarFeatures, impossibleTravel, maliciousIPAddress, etc.) when the custom anomaly table is unavailable. Results are formatted to match Q2's output shape for consistent report rendering.

**Report note:** When Q2b is used instead of Q2, include this in the report header: `📊 Data Source: Identity Protection (SigninLogs risk events) — custom anomaly table not available in this workspace.`

---

### Query 3: Risky Sign-Ins & Identity Protection Summary

🔐 **Risk posture snapshot** — Fleet-level summary of Identity Protection risk signals.

**Tool:** `mcp_sentinel-data_query_lake`

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium") or RiskState in ("atRisk", "confirmedCompromised")
| summarize 
    RiskySignIns = count(),
    DistinctUsers = dcount(UserPrincipalName),
    HighRisk = countif(RiskLevelDuringSignIn == "high"),
    MediumRisk = countif(RiskLevelDuringSignIn == "medium"),
    AtRisk = countif(RiskState == "atRisk"),
    Compromised = countif(RiskState == "confirmedCompromised"),
    TopUsers = make_set(UserPrincipalName, 10),
    TopRiskEvents = make_set(RiskEventTypes_V2, 10)
| project RiskySignIns, DistinctUsers, HighRisk, MediumRisk, 
    AtRisk, Compromised, TopUsers, TopRiskEvents
```

**Purpose:** Single-row summary of risky sign-in activity — how many, how severe, who's affected. Surfaces users in `atRisk` or `confirmedCompromised` states that need immediate admin attention.

**Verdict logic:**
- 🔴 Escalate: `Compromised > 0` or `HighRisk > 10`
- 🟠 Investigate: `AtRisk > 0` or `HighRisk > 0`
- 🟡 Monitor: `MediumRisk > 0` only
- ✅ Clear: 0 risky sign-ins

---

### Query 4: Fleet-Wide Device Process Drift

💻 **Endpoint behavioral baseline** — Per-device drift scores computed in-query (7d baseline vs 1d recent), returned pre-ranked.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| extend IsRecent = Timestamp >= ago(1d)
| summarize
    BL_Events = countif(not(IsRecent)),
    RC_Events = countif(IsRecent),
    BL_Procs = dcountif(FileName, not(IsRecent)),
    RC_Procs = dcountif(FileName, IsRecent),
    BL_Accts = dcountif(AccountName, not(IsRecent)),
    RC_Accts = dcountif(AccountName, IsRecent),
    BL_Chains = dcountif(strcat(InitiatingProcessFileName, "→", FileName), not(IsRecent)),
    RC_Chains = dcountif(strcat(InitiatingProcessFileName, "→", FileName), IsRecent),
    BL_Comps = dcountif(ProcessVersionInfoCompanyName, not(IsRecent)),
    RC_Comps = dcountif(ProcessVersionInfoCompanyName, IsRecent)
    by DeviceName
| where RC_Events > 0 and BL_Events > 0
| extend
    VolDrift = round(RC_Events * 600.0 / max_of(BL_Events, 1), 0),
    ProcDrift = round(RC_Procs * 100.0 / max_of(BL_Procs, 1), 0),
    AcctDrift = round(RC_Accts * 100.0 / max_of(BL_Accts, 1), 0),
    ChainDrift = round(RC_Chains * 100.0 / max_of(BL_Chains, 1), 0),
    CompDrift = round(RC_Comps * 100.0 / max_of(BL_Comps, 1), 0)
| extend DriftScore = round(VolDrift * 0.30 + ProcDrift * 0.25 + AcctDrift * 0.15 + ChainDrift * 0.20 + CompDrift * 0.10, 0)
| order by DriftScore desc
| take 10
| project DeviceName, DriftScore, VolDrift, ProcDrift, AcctDrift, ChainDrift, CompDrift
```

**Purpose:** Returns the top 10 devices ranked by composite drift score, pre-computed in KQL. No LLM-side math required — just interpret the returned scores.

**Drift formula notes:**
- **Volume (`VolDrift`):** `RC_Events * 600 / BL_Events` — multiplies recent by 600 (= 100 × 6 baseline days) to normalize to a per-day rate before computing the percentage. This is the only metric that needs time normalization because event counts scale linearly with time.
- **Dcount metrics (`ProcDrift`, `AcctDrift`, `ChainDrift`, `CompDrift`):** `RC_Dim * 100 / BL_Dim` — compared directly WITHOUT dividing baseline by 6. Distinct counts do NOT scale linearly with time (seeing 4 unique accounts over 6 days ≠ 0.67 accounts/day). The 6-day baseline captures the "universe" of distinct values; a single day shows what fraction was active. 100% = normal, >100% = new values appeared.
- **Weights:** Volume 30%, Processes 25%, Chains 20%, Accounts 15%, Companies 10%.

---

### Query 5: Rare Process Chain Singletons

💻 **Threat hunting** — Parent→child process combinations appearing fewer than 3 times in 90 days.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| summarize 
    Count = count(),
    UniqueDevices = dcount(DeviceName),
    SampleDevice = take_any(DeviceName),
    SampleUser = strcat(take_any(AccountDomain), "\\", take_any(AccountName)),
    SampleChildCmd = take_any(ProcessCommandLine),
    GrandparentProcess = take_any(InitiatingProcessParentFileName),
    LastSeen = max(Timestamp)
    by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| where Count < 3
| order by Count asc, UniqueDevices asc
| take 20
```

**Purpose:** Surfaces the 20 rarest process chains — singletons and near-singletons. Effective for spotting LOLBin abuse, malware execution, or novel attack tooling. Review `SampleChildCmd` for suspicious command-line patterns.

**Verdict logic:**
- 🟠 Investigate: Any singleton with suspicious parent (cmd.exe, powershell.exe, wscript.exe, mshta.exe, rundll32.exe) or child running from temp/user profile directories
- 🟡 Monitor: Rare chains from system/update processes (version-stamped binaries, Azure VM agents)
- ✅ Clear: All rare chains are explainable infrastructure artifacts

---

### Query 6: Internet-Facing Critical Assets with Vulnerability Exposure

🛡️ **Attack surface** — ExposureGraph snapshot of critical assets, flagging internet exposure and RCE/PrivEsc vulnerabilities.

**Tool:** `RunAdvancedHuntingQuery`

```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))
| extend critLevel = toint(rawData.criticalityLevel.criticalityLevel)
| where isnotnull(critLevel) and critLevel < 4
| extend IsInternetFacing = tobool(rawData.IsInternetFacing) or tobool(rawData.exposedToInternet)
| extend VulnRCE = tobool(rawData.highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution)
| extend VulnPrivEsc = tobool(rawData.highRiskVulnerabilityInsights.VulnerableToPrivilegeEscalation)
| project 
    DeviceName = NodeName,
    CriticalityLevel = critLevel,
    IsInternetFacing,
    VulnRCE,
    VulnPrivEsc,
    NodeLabel
| order by IsInternetFacing desc, CriticalityLevel asc
| take 25
```

**Purpose:** Returns the critical asset inventory (criticality 0–3) with internet-facing status and vulnerability flags. An internet-facing critical asset with RCE vulnerability is the highest-priority finding in this entire skill.

**Verdict logic:**
- 🔴 Escalate: Any `IsInternetFacing == true` AND (`VulnRCE == true` or `VulnPrivEsc == true`)
- 🟠 Investigate: Any `IsInternetFacing == true` (without known vulns)
- 🟡 Monitor: Critical assets exist but none internet-facing
- ✅ Clear: All critical assets properly segmented, no internet exposure

---

### Query 7: SPN Behavioral Drift (90d Baseline vs 7d Recent)

🤖 **Automation monitoring** — Composite drift score across 5 dimensions for service principals.

**Tool:** `mcp_sentinel-data_query_lake` (needs >30d lookback)

```kql
let BL_Start = ago(97d); let BL_End = ago(7d);
let RC_Start = ago(7d); let RC_End = now();
let BL = AADServicePrincipalSignInLogs
| where TimeGenerated between (BL_Start .. BL_End)
| summarize 
    BL_Vol = count(),
    BL_Res = dcount(ResourceDisplayName),
    BL_IPs = dcount(IPAddress),
    BL_Loc = dcount(Location),
    BL_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
let RC = AADServicePrincipalSignInLogs
| where TimeGenerated between (RC_Start .. RC_End)
| summarize 
    RC_Vol = count(),
    RC_Res = dcount(ResourceDisplayName),
    RC_IPs = dcount(IPAddress),
    RC_Loc = dcount(Location),
    RC_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
RC | join kind=inner BL on ServicePrincipalId
| extend 
    VolDrift = round(RC_Vol * 100.0 / max_of(BL_Vol, 10), 0),
    ResDrift = round(RC_Res * 100.0 / max_of(BL_Res, 3), 0),
    IPDrift = round(RC_IPs * 100.0 / max_of(BL_IPs, 3), 0),
    LocDrift = round(RC_Loc * 100.0 / max_of(BL_Loc, 2), 0),
    FailDrift = round(RC_Fail * 100.0 / max_of(BL_Fail, 5), 0)
| extend DriftScore = round((VolDrift*0.20 + ResDrift*0.25 + IPDrift*0.25 + LocDrift*0.15 + FailDrift*0.15), 0)
| where DriftScore > 120
| order by DriftScore desc
| take 10
```

**Purpose:** Identifies service principals with significant behavioral changes from their 90-day baseline. The weighted drift score combines Volume (20%), Resources (25%), IPs (25%), Locations (15%), and Failure Rate (15%). Scores above 150 are flagged, above 250 are critical.

**Verdict logic:**
- 🔴 Escalate: Any SPN with `DriftScore > 250` or `IPDrift > 400%`
- 🟠 Investigate: `DriftScore > 150`
- 🟡 Monitor: `DriftScore 120–150` (minor expansion)
- ✅ Clear: No SPNs above threshold

**Drill-down:** Use `scope-drift-detection/spn` skill for full investigation of flagged SPNs.

---

### Query 8: Inbound Email Threat Snapshot

📧 **Email posture** — Single-row summary of inbound email volume, threat breakdown, and delivered threats.

**Tool:** `RunAdvancedHuntingQuery`

```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| summarize
    TotalInbound = count(),
    Clean = countif(isempty(ThreatTypes)),
    Phish = countif(ThreatTypes has "Phish"),
    Malware = countif(ThreatTypes has "Malware"),
    Spam = countif(ThreatTypes has "Spam"),
    HighConfPhish = countif(ConfidenceLevel has "High" and ThreatTypes has "Phish"),
    Blocked = countif(DeliveryAction == "Blocked"),
    Delivered = countif(DeliveryAction == "Delivered"),
    PhishDelivered = countif(ThreatTypes has "Phish" and DeliveryAction == "Delivered"),
    DistinctSenders = dcount(SenderFromAddress),
    DistinctRecipients = dcount(RecipientEmailAddress)
```

**Purpose:** Instant C-level email posture briefing. The key escalation metric is `PhishDelivered` — phishing emails that bypassed all protections and reached mailboxes.

**Verdict logic:**
- 🔴 Escalate: `PhishDelivered > 5` or `Malware > 0` delivered
- 🟠 Investigate: `PhishDelivered > 0` (any phishing reached mailboxes)
- 🟡 Monitor: Phishing detected but 100% blocked/junked
- ✅ Clear: 0 phishing, 0 malware

**Drill-down:** Use `email-threat-posture` skill for full email security analysis including ZAP, Safe Links, and authentication breakdown.

---

### Query 9: UEBA/MCAS Behavioral Detections

📈 **Sub-alert signals** — Behavioral detections from MCAS and Sentinel UEBA that didn't generate alerts.

**Tool:** `RunAdvancedHuntingQuery`

**⚠️ Two-stage query pattern:** The original single-query join (`BehaviorInfo ↔ BehaviorEntities` with `make_set(strcat(coalesce(...)))`) times out via the Advanced Hunting Graph API (~30s limit) on workspaces with moderate-to-high behavior volume. The fix: **Stage 1** queries `BehaviorInfo` alone for the summary dashboard. **Stage 2** (optional, only if Stage 1 returns 🟠/🔴 findings) queries `BehaviorEntities` for specific `BehaviorId` values to enrich the report with entity details.

**Stage 1 — Summary (always run):**

```kql
BehaviorInfo
| where Timestamp > ago(7d)
| summarize 
    DetectionCount = count(),
    DateRange = strcat(format_datetime(min(Timestamp), "yyyy-MM-dd"), " to ", format_datetime(max(Timestamp), "yyyy-MM-dd"))
    by ActionType, ServiceSource
| order by DetectionCount desc
| take 15
```

**Stage 2 — Entity enrichment (run only for flagged ActionTypes):**

```kql
let FlaggedBehaviors = BehaviorInfo
| where Timestamp > ago(7d)
| where ActionType in ("UnusualAdditionOfCredentialsToAnOauthApp", "ImpossibleTravelActivity", "MassDownload")
| project BehaviorId;
BehaviorEntities
| where Timestamp > ago(7d)
| where BehaviorId in (FlaggedBehaviors)
| where EntityType in ("User", "Ip", "CloudApplication")
| summarize 
    Entities = make_set(
        strcat(EntityType, ":", coalesce(AccountUpn, AccountName, RemoteIP, Application, DeviceName, "")), 5)
    by BehaviorId
| take 20
```

**Purpose:** Surfaces MCAS behavioral signals below the alert threshold — impossible travel, mass downloads, unusual OAuth credential additions, multi-failed logins. These are early-warning indicators that complement SecurityAlert. The two-stage design keeps Stage 1 fast (<5s) and avoids the expensive cross-table join unless specific high-priority behaviors are detected.

**Verdict logic:**
- 🟠 Investigate: `UnusualAdditionOfCredentialsToAnOauthApp` or `ImpossibleTravelActivity` detected → run Stage 2
- 🟡 Monitor: `MultipleFailedLoginAttempts` or `MassDownload` detected → run Stage 2
- ✅ Clear: No behavioral detections (or MCAS/UEBA not deployed — note as ❓)

**Known limitation:** `BehaviorEntities` does not have an `EntityName` column. Use `AccountUpn`, `AccountName`, `RemoteIP`, `Application`, or `DeviceName` depending on `EntityType`. The `coalesce()` pattern in Stage 2 handles this. Some `ActionType` values from MDE appear as GUIDs rather than human-readable names — report them as-is with the ServiceSource for context.

---

### Query 10: Password Spray / Brute-Force Detection

🔐 **Auth spray detection (T1110.003 / T1110.001)** — Identifies IPs targeting multiple users with failed auth across Entra ID cloud sign-ins AND RDP/SSH/network logons on endpoints.

**Tool:** `RunAdvancedHuntingQuery`

```kql
let EntraSpray = SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType in ("50126", "50053", "50057")
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(UserPrincipalName),
    SampleTargets = make_set(UserPrincipalName, 5),
    Protocols = make_set(AppDisplayName, 3),
    Countries = make_set(Location, 3)
    by SourceIP = IPAddress
| where TargetUsers >= 5
| extend Surface = "Entra ID";
let EndpointBrute = DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| where LogonType in ("RemoteInteractive", "Network")
| where isnotempty(RemoteIP)
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(AccountName),
    SampleTargets = make_set(AccountName, 5),
    Protocols = make_set(strcat(LogonType, " → ", DeviceName), 3),
    Countries = dynamic(["—"])
    by SourceIP = RemoteIP
| where FailedAttempts >= 10
| extend Surface = "Endpoint (RDP/SSH)";
union EntraSpray, EndpointBrute
| order by TargetUsers desc, FailedAttempts desc
| take 15
```

**Purpose:** Detects password spray (1 IP → many users, MITRE T1110.003) and brute-force (1 IP → high failure count, T1110.001) across two surfaces:
- **Entra ID:** Cloud sign-in failures (50126=bad password, 50053=locked account, 50057=disabled account). An IP targeting ≥5 distinct users with these errors is a strong spray signal. `Protocols` reveals if legacy auth (POP/IMAP/SMTP) is being targeted.
- **Endpoint:** RDP (`RemoteInteractive`) and SSH/SMB (`Network`) failed logons on MDE-enrolled devices. Threshold of ≥10 failures catches brute-force against exposed endpoints.

**Verdict logic:**
- 🔴 Escalate: Any IP targeting >25 Entra users OR >100 endpoint failures from a single IP
- 🟠 Investigate: Any spray/brute-force pattern detected (meets thresholds)
- ✅ Clear: 0 results — no spray/brute-force patterns detected

**Drill-down:** Use `user-investigation` skill for targeted users, `ioc-investigation` for source IPs.

---

### Query 11: High-Impact Privileged Operations

🔑 **Admin activity monitoring** — Recent high-privilege operations: role assignments, credential additions, consent grants, CA policy changes, password resets.

**Tool:** `mcp_sentinel-data_query_lake`

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("role", "credential", "consent", "Conditional Access", "password", "certificate")
| where Result == "success"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend Target = tostring(parse_json(tostring(TargetResources[0])).displayName)
| summarize 
    Count = count(),
    Operations = make_set(OperationName, 5),
    Targets = make_set(Target, 5),
    LatestTime = max(TimeGenerated)
    by Actor
| order by Count desc
| take 15
```

**Purpose:** Shows who's been performing privileged admin operations. Unexpected actors or unusual volume (e.g., 36 password resets from one user in a week) warrant investigation. System-initiated operations (empty Actor) are normal PIM lifecycle events.

**Verdict logic:**
- 🟠 Investigate: Unexpected user appearing as Actor; high-volume single-user operations
- 🟡 Monitor: Normal PIM/system operations; expected admin activity
- ✅ Clear: Only system-driven operations with expected volume

---

### Query 12: Exploitable CVEs (CVSS ≥ 8.0) Across Fleet

🛡️ **Vulnerability patch priority** — Top exploitable critical CVEs with affected device count.

**Tool:** `RunAdvancedHuntingQuery`

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where IsExploitAvailable == true
| where CvssScore >= 8.0
| summarize 
    AffectedDevices = dcount(DeviceName),
    SampleDevices = make_set(DeviceName, 3),
    Software = make_set(SoftwareName, 3)
    by CveId, VulnerabilitySeverityLevel, CvssScore
| order by AffectedDevices desc, CvssScore desc
| take 15
```

**Purpose:** Instant "what should we patch today" list. Ranks exploitable CVEs by fleet impact (devices affected × CVSS severity). Focus on CVEs with public exploits affecting the most devices.

**Verdict logic:**
- 🔴 Escalate: Any CVE with `CvssScore >= 9.0` AND `AffectedDevices > 10`
- 🟠 Investigate: CVE with `CvssScore >= 8.0` AND `AffectedDevices > 5`
- 🟡 Monitor: Exploitable CVEs exist but affect < 5 devices
- ✅ Clear: No exploitable CVEs with CVSS ≥ 8.0 (unlikely but possible in small environments)

**Drill-down:** Use `exposure-investigation` skill for full vulnerability posture assessment.

---

## Post-Processing

### Device Drift Score Interpretation (Q4)

Q4 returns pre-computed drift scores directly from KQL — **no LLM-side math is needed**. Simply present the returned table and apply verdicts using this scale:

| DriftScore | Interpretation | Verdict |
|------------|---------------|--------|
| < 80 | Contracting activity (device may be idle/decommissioned) | 🔵 Informational |
| 80–120 | Stable (normal operating range) | ✅ Clear |
| 120–150 | Minor behavioral expansion | 🟡 Monitor |
| 150–250 | Significant deviation | 🟠 Investigate |
| 250+ | Major anomaly — immediate investigation | 🔴 Escalate |

**Fleet-wide context:** If ALL devices show similar scores (e.g., all between 80–120 or all between 120–150), the fleet is behaving uniformly and the verdict should be downgraded one level. Drift is most meaningful when individual devices diverge from the fleet average.

**⛔ DO NOT manually recompute drift scores.** The KQL query handles Volume normalization (÷6 baseline days) and dcount comparison (direct ratio). Trust the returned `DriftScore` column.

### Cross-Query Correlation

After all queries complete, check these correlation patterns and escalate priority when found:

| Pattern | Queries | Implication | Action |
|---------|---------|-------------|--------|
| Same user in anomalies AND risky sign-ins | Q2 + Q3 | Corroborated identity compromise signal | Escalate to 🔴 |
| SPN drift AND unusual OAuth credential addition | Q7 + Q9 | App credential abuse / persistence | Escalate to 🔴 |
| Device with rare process chain AND exploitable CVE | Q5 + Q12 | Potential active exploitation | Escalate to 🔴 |
| Incident entity matches anomaly/risk user | Q1 + Q2/Q3 | Known incident may be expanding | Link findings in report |
| Spray IP overlaps with anomaly/risk user | Q10 + Q2/Q3 | Spray target already flagged by Identity Protection | Escalate to 🔴 |

---

## Query File Recommendations

After assigning verdicts and generating recommendations, search the `queries/` library for pre-built hunting campaigns that target the TTPs and threat patterns surfaced by today's scan. **Only run this step when at least one 🔴 or 🟠 verdict exists.**

### Keyword Extraction Rules

Extract search keywords deterministically from 🔴/🟠 findings:

| Finding Source | Keywords to Extract |
|---------------|--------------------|
| Q1 (Incidents) | MITRE tactic names from `Tactics` column (e.g., "lateral movement", "credential access"), alert titles |
| Q2/Q2b (Identity) | "anomaly", "sign-in", "identity", "phishing" if geo-novelty flags set |
| Q3 (Identity Protection) | "risky sign-in", "token", "aitm", "phishing" if risk detail contains these |
| Q5 (Rare Processes) | Process names from singleton chains (e.g., "mimikatz", "rclone", "psexec"), "rare process" |
| Q7 (SPN Drift) | "service principal", "app registration", "credential" |
| Q8 (Email) | "phishing", "email", "spam", "malware" if delivered threats > 0 |
| Q9 (UEBA) | ActionType values (e.g., "impossible travel", "mass download", "brute force") |
| Q10 (Auth Spray) | "brute force", "password spray", "RDP", "credential" |
| Q12 (CVEs) | Specific CVE IDs from results, software names from `SoftwareName` column |

### Search Procedure

1. Collect keywords from all 🔴/🟠 domains using the extraction rules above
2. Run `grep_search` with each keyword (or combined with `|` alternation) scoped to `queries/**`
3. Deduplicate matched files — a file matching multiple keywords ranks higher
4. Read the first 10 lines of each matched file to extract the title and description from the metadata header
5. Select the **top 3–5 most relevant** files, ranked by number of keyword matches

### Report Output Block

Insert this section between **Recommended Actions** and **Appendix** in both inline and file reports:

```markdown
## 📂 Recommended Query Files for Follow-Up Hunting

<If matching query files found:>

Based on today's findings, these query files contain pre-built hunting campaigns targeting related TTPs and IOCs:

| Query File | Relevance | Matched Findings |
|-----------|-----------|------------------|
| [<Title>](queries/<subfolder>/<filename>.md) | <matched keywords> | Q<N>: <finding summary> |
| ... | ... | ... |

> 💡 **Follow-up prompt:** Open a query file above and ask:
> *"Run a hunting campaign against these TTPs and IOCs and summarize any key findings"*

<If no matching query files found:>

📂 No matching query files found for today's findings. Consider authoring new hunting queries:
> *"Read this threat intel article: <URL> — extract TTPs and IOCs, then write, test, and tune a queries file for reusable threat hunts"*
```

**Link format:** Use workspace-relative paths — `queries/endpoint/storm_1175_medusa_ransomware_campaign.md` — so links are clickable in VS Code chat.

---

## Output Modes

### Mode 1: Inline Chat Summary

Render the full Threat Pulse Dashboard directly in the chat response. Best for quick daily checks, SOC standup briefings, or when you need a quick status scan.

### Mode 2: Markdown File Report

Save a comprehensive report to disk at:
```
reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md
```

### Mode 3: Both

Generate the markdown file AND provide an inline summary in chat.

**Always ask the user which mode before generating output. Default to Mode 1 (inline) if user says "just run it".**

---

## Inline Report Template

Render the following sections in order. Omit sections only if explicitly noted as conditional.

> **🔴 URL Rule:** All hyperlinks in the report MUST be copied verbatim from the [URL Registry](#-url-registry--canonical-links-for-report-generation) above. Do NOT generate, recall from memory, or paraphrase any URL.

````markdown
# 🔍 Threat Pulse — <WorkspaceName> | <YYYY-MM-DD>

**Generated:** <YYYY-MM-DD HH:MM> UTC
**Workspace:** <WorkspaceName> (`<WorkspaceId>`)
**Scan Duration:** ~<N>s | **Queries:** 12 | **Domains:** 9

---

## Dashboard Summary

| # | Domain | Status | Key Finding |
|---|--------|--------|-------------|
| Q1 | 🔴 **Incidents** | <verdict> | <1-line finding> |
| Q2 | 🔐 **Sign-In Anomalies** | <verdict> | <1-line finding> |
| Q3 | 🔐 **Identity Protection** | <verdict> | <1-line finding> |
| Q4 | 💻 **Device Drift** | <verdict> | <1-line finding> |
| Q5 | 💻 **Rare Processes** | <verdict> | <1-line finding> |
| Q6 | 🛡️ **Critical Assets** | <verdict> | <1-line finding> |
| Q7 | 🤖 **SPN Drift** | <verdict> | <1-line finding> |
| Q8 | 📧 **Email Threats** | <verdict> | <1-line finding> |
| Q9 | 📈 **UEBA Behaviors** | <verdict> | <1-line finding> |
| Q10 | � **Auth Spray** | <verdict> | <1-line finding> |
| Q11 | 🔑 **Privileged Ops** | <verdict> | <1-line finding> |
| Q12 | 🛡️ **Exploitable CVEs** | <verdict> | <1-line finding> |

<Where verdict is one of: 🔴 Escalate | 🟠 Investigate | 🟡 Monitor | ✅ Clear | ❓ No Data>

---

## Detailed Findings

<For each query with results (skip empty sections is PROHIBITED — every query gets a section):>

### <emoji> Q<N> — <Domain Name> (<lookback>)

<If results found:>

| <columns from query> |
|---|
| <data rows, max 10 for inline> |

**Q1 column format (mandatory):**

| Incident | Title | Age (days) | Alerts | Owner | Tactics |

Where **Incident** renders the XDR portal link: `[XDR #<ProviderIncidentId>](https://security.microsoft.com/incidents/<ProviderIncidentId>)`. Do NOT use raw `ProviderIncidentId` as a column header — always display as `Incident`. Unassigned incidents show `⚠️ Unassigned` in the Owner column.

<Contextual analysis with emoji-coded risk assessment>

<If 0 results:>

✅ No <finding type> detected in the last <lookback>.
- Checked: <table name> (0 matches)

---

## Cross-Query Correlations

<If correlations found between queries per the Post-Processing rules:>

| Pattern | Evidence | Escalation |
|---------|----------|------------|
| <description> | Q<N> user X also in Q<M> | 🔴 Priority upgraded |

<If no correlations:>

✅ No cross-domain correlations detected across query results.

---

## 🎯 Recommended Actions

| Priority | Action | Trigger | Deep-Dive Skill |
|----------|--------|---------|-----------------|
| 🔴 **1** | <action> | Q<N>: <evidence> | `<skill-name>` |
| 🟠 **2** | <action> | Q<N>: <evidence> | `<skill-name>` |
| 🟡 **3** | <action> | Q<N>: <evidence> | `<skill-name>` |

<Recommendations MUST reference specific query findings and name the skill for drill-down.>

---

## 📂 Recommended Query Files for Follow-Up Hunting

<Render this section per the Query File Recommendations procedure. Only appears when 🔴/🟠 verdicts exist.>

<If all verdicts are ✅/🟡, omit this section entirely.>

---

## Appendix: Query Execution Summary

| Query | Domain | Records | Data Source | Notes |
|-------|--------|---------|-------------|-------|
| Q1 | Incidents | <N> | Data Lake | |
| Q2/Q2b | Identity Anomalies | <N> | Data Lake | <"Custom table" or "Identity Protection fallback"> |
| Q3 | Identity Protection | <N> | Data Lake | |
| Q4 | Device Drift | 10 | Advanced Hunting | Pre-ranked top 10 by DriftScore |
| Q5 | Rare Processes | <N> | Advanced Hunting | |
| Q6 | Critical Assets | <N> | Advanced Hunting | <N internet-facing> |
| Q7 | SPN Drift | <N> | Data Lake | <N SPNs above threshold> |
| Q8 | Email Threats | 1 | Advanced Hunting | Single-row aggregate |
| Q9 | UEBA Behaviors | <N> | Advanced Hunting | |
| Q10 | Auth Spray | <N> | Advanced Hunting | Entra ID + Endpoint surfaces |
| Q11 | Privileged Ops | <N> | Data Lake | |
| Q12 | Exploitable CVEs | <N> | Advanced Hunting | |
````

---

## Markdown File Report Template

When outputting to markdown file, use the same structure as the Inline Report Template above, saved to:

```
reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md
```

Include the following additional sections in the file report that are omitted from inline:

1. **Full data tables** — No row limits (inline caps at 10 rows per table; file includes all results)
2. **Device Drift Score Table** — Full ranked list of all devices with computed drift scores
3. **Rare Process Chain Details** — Full command-line samples for all 20 singletons
4. **CVE Detail Table** — All 15 CVEs with affected device lists

---

## Known Pitfalls

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| `Signinlogs_Anomalies_KQL_CL` doesn't exist | Q2 fails | Silently fall back to Q2b (Identity Protection) |
| `SecurityAlert.Status` is always "New" | Misleading incident triage | Q1 joins SecurityIncident for real Status |
| `BehaviorEntities` has no `EntityName` column | Q9 fails with SemanticError | Use `coalesce(AccountUpn, AccountName, RemoteIP, Application, DeviceName)` |
| Q9 join (`BehaviorInfo ↔ BehaviorEntities`) times out via AH Graph API | User cancellation / ~30s timeout on 30d join with `make_set(strcat(coalesce(...)))` | Two-stage pattern: Stage 1 queries BehaviorInfo alone (7d); Stage 2 enriches specific BehaviorIds only when 🟠/🔴 findings exist |
| Q9 `ActionType` values from MDE appear as GUIDs | Dashboard shows opaque IDs instead of human-readable names | Report GUIDs as-is with ServiceSource; only MCAS behaviors use readable names (e.g., `ImpossibleTravelActivity`) |
| `ExposureGraphNodes.NodeProperties` requires double `parse_json()` | Null values if single parse | Q6 uses `parse_json(tostring(parse_json(...)))` pattern |
| Q7 (SPN drift) takes ~35s due to 97d lookback | Slow query | Acceptable — runs in parallel with other Data Lake queries |
| `DeviceTvmSoftwareVulnerabilities` is AH-only | Data Lake returns "table not found" | Q12 must use `RunAdvancedHuntingQuery` |
| `EmailEvents` uses `Timestamp` not `TimeGenerated` | SemanticError if wrong column | Q8 uses `Timestamp` (XDR-native table) |
| `AuditLogs.InitiatedBy` is a dynamic field | `has` operator fails without `tostring()` | Q11 uses `parse_json(tostring(...))` pattern |
| Q4 drift scores | Previously required LLM-side math, causing reasoning overhead | Drift scores now computed in-query; LLM only interprets returned `DriftScore` column |

---

## Quality Checklist

Before rendering the final report, verify:

- [ ] All 12 queries executed (or fallback used for Q2)
- [ ] Every domain has a verdict row in the Dashboard Summary (no omissions)
- [ ] Every ✅ Clear verdict cites the specific table queried and "0 results"
- [ ] Every 🔴/🟠 verdict cites specific evidence (counts, names, scores)
- [ ] All incidents include clickable `https://security.microsoft.com/incidents/{ProviderIncidentId}` URLs
- [ ] Cross-query correlations checked (minimum: Q2+Q3 user overlap, Q7+Q9 SPN+OAuth overlap)
- [ ] Recommended Actions table includes at least 1 item per 🔴/🟠 domain
- [ ] Each recommendation references a specific drill-down skill
- [ ] Q2b fallback noted in report if custom table was unavailable
- [ ] No fabricated data — all findings trace to actual query results
- [ ] Query file recommendations searched for 🔴/🟠 domains (or section omitted if all ✅/🟡)

---

## SVG Dashboard Generation

After completing the Threat Pulse report, the user may request an SVG visualization. Use the `svg-dashboard` skill in **freeform mode** with this data mapping:

| SVG Component | Data Source |
|---------------|-------------|
| **KPI Cards (top row)** | Total incidents (Q1), Risky users (Q3), Phish delivered (Q8), Exploitable CVEs (Q12) |
| **Score Card** | Not applicable (Threat Pulse doesn't compute a single composite score) |
| **Donut Chart** | Email threat composition: Clean/Phish/Spam/Malware from Q8 |
| **Bar Chart** | SPN drift scores from Q7 (top 5 SPNs) |
| **Table** | Dashboard Summary verdicts (12 rows) |
| **Recommendation Cards** | Top 3 recommended actions |

Refer to the `svg-dashboard` SKILL.md for component specifications and rendering instructions.
