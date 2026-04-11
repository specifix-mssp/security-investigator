---
name: identity-posture
description: 'Use this skill when asked to audit, assess, or report on identity security posture across the organization. Triggers on keywords like "identity posture", "identity security report", "account hygiene", "stale accounts", "privileged accounts", "password posture", "identity providers", "multi-provider identity", "identity sprawl", "service accounts", "deleted accounts with roles", "identity risk", "account status", "cross-IdP", "honeytoken", "sensitive accounts", or when investigating identity lifecycle, privilege distribution, credential hygiene, or multi-provider account correlation. This skill queries the IdentityAccountInfo table in Advanced Hunting (with IdentityInfo and IdentityLogonEvents enrichment) to produce a comprehensive identity security posture assessment covering account inventory by provider, privileged account audit, stale/deleted account hygiene, password posture, risk distribution, multi-provider identity linking, MDI tag analysis, and department-level insights. Supports inline chat and markdown file output.'
threat_pulse_domains: [identity]
drill_down_prompt: 'Run identity posture report — account hygiene, privilege distribution, stale accounts'
---

# Identity Security Posture — Instructions

## Purpose

This skill audits the **identity security posture** across your organization using the `IdentityAccountInfo` table in Microsoft Defender XDR Advanced Hunting, enriched with `IdentityInfo` and `IdentityLogonEvents` for password policy and logon activity context.

Modern organizations use multiple identity providers (Entra ID, Active Directory, Okta, SailPoint, CyberArk, Ping, etc.). `IdentityAccountInfo` is the **only table** that provides a unified identity graph across these providers, linking accounts to a single `IdentityId`. This skill systematically evaluates the security posture of that identity fabric.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔍 **Identity Inventory** | How many accounts exist? Across which providers? What types and statuses? |
| 👑 **Privileged Account Audit** | Who holds high-privilege roles? Across which providers? Are they permanent? |
| 🗑️ **Stale & Deleted Account Hygiene** | Which enabled accounts have no logon activity? Do deleted accounts retain permissions? |
| 🔑 **Password Posture** | Password age distribution, PasswordNeverExpires/PasswordNotRequired flags (AD accounts via IdentityInfo join) |
| 🟠 **Risk Distribution** | How are identity risk levels distributed? Which high-risk accounts are still active? |
| 🔗 **Multi-Provider Identity Linking** | Which identities span multiple IdPs? Are there status mismatches across providers? |
| 🏷️ **Sensitive & Honeytoken Accounts** | Which accounts are MDI-tagged? Are sensitive accounts properly protected? |
| 🏢 **Organizational Context** | Account distribution by department, service account inventory |

**Primary data source:** `IdentityAccountInfo` table (Advanced Hunting) — currently in **Preview**.

**Enrichment tables:**
- `IdentityInfo` — Adds `UserAccountControl` (PasswordNeverExpires, PasswordNotRequired), `DistinguishedName`, `RiskLevel`, `BlastRadius`, `PrivilegedEntraPimRoles` (Preview)
- `IdentityLogonEvents` — Last logon timestamps across AD, Entra, Okta, SailPoint, M365 apps
- `SigninLogs` — Last Entra ID sign-in for stale account detection (via Data Lake for 90d+ lookback)

**References:**
- [Microsoft Docs — IdentityAccountInfo table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityaccountinfo-table)
- [Microsoft Docs — IdentityInfo table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table)
- [MDI Accounts Security Posture Assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts)
- [MDI Hybrid Security Posture Assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/hybrid-security)
- [Alex Verboon — AD Password Security Posture Assessment](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/MDI-Identity-Password%20Security%20Posture%20Assessment.md)

### 🔴 URL Registry — Canonical Links for Report Generation

**MANDATORY:** When generating reports, copy URLs **verbatim** from this registry. NEVER construct, guess, or paraphrase a URL. If a URL is not in this registry, omit the hyperlink entirely and use plain text.

| Label | Canonical URL |
|-------|---------------|
| `DOCS_IDENTITYACCOUNTINFO` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityaccountinfo-table` |
| `DOCS_IDENTITYINFO` | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table` |
| `DOCS_MDI_ACCOUNTS` | `https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts` |
| `DOCS_MDI_HYBRID` | `https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/hybrid-security` |
| `DOCS_MDI_INFRA` | `https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/identity-infrastructure` |
| `GITHUB_VERBOON_PWD` | `https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/MDI-Identity-Password%20Security%20Posture%20Assessment.md` |

---

## Why Identity Posture Matters

Identity is the new perimeter. Attackers consistently target credentials, stale accounts, and over-privileged identities as the path of least resistance into enterprise environments. Key risks this skill detects:

| Risk | Impact | Skill Detection |
|------|--------|-----------------|
| **Stale accounts** | Dormant accounts with active permissions are prime targets for credential stuffing and lateral movement | Q5 (Stale Account Detection) |
| **Deleted accounts with residual permissions** | Accounts that are deleted but retain group memberships and role assignments create orphan access | Q6 (Deleted Account Hygiene) |
| **Permanent privileged roles** | Standing Global Admin / Security Admin roles violate least-privilege and increase blast radius | Q4 (Privileged Account Audit) |
| **Password policy gaps** | PasswordNeverExpires and PasswordNotRequired on AD accounts undermine credential rotation | Q7 (Password Posture) |
| **Multi-provider identity sprawl** | Same person with accounts across AAD + AD + Okta + CyberArk with inconsistent status/permissions | Q8 (Multi-Provider Linking) |
| **High-risk active accounts** | Accounts flagged High risk by Identity Protection that remain active and privileged | Q9 (Risk Distribution) |
| **Unprotected sensitive accounts** | MDI-tagged Sensitive/Honeytoken accounts without appropriate monitoring | Q10 (MDI Tags) |

This skill maps directly to the following **MDI Security Posture Assessments** (see [Accounts assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts)):
- Remove stale Active Directory accounts
- Entra ID privileged users also privileged in AD
- Identify service accounts in privileged groups
- Locate accounts in built-in Operator Groups
- Accounts with passwords older than 180 days

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** — Mandatory rules
2. **[Table Schema Reference](#table-schema-reference)** — IdentityAccountInfo columns
3. **[Identity Posture Score Formula](#identity-posture-score-formula)** — Composite risk scoring
4. **[Execution Workflow](#execution-workflow)** — Phase-by-phase query plan
5. **[Sample KQL Queries](#sample-kql-queries)** — All queries (Q1–Q12)
6. **[Output Modes](#output-modes)** — Inline vs Markdown report
7. **[Inline Report Template](#inline-report-template)** — Chat-rendered format
8. **[Markdown File Report Template](#markdown-file-report-template)** — Disk-saved format
9. **[SVG Dashboard Generation](#svg-dashboard-generation)** — Visual dashboard from report
10. **[Known Pitfalls](#known-pitfalls)** — Schema quirks and edge cases
11. **[Quality Checklist](#quality-checklist)** — Pre-delivery validation

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **ALWAYS use `RunAdvancedHuntingQuery`** — The `IdentityAccountInfo` table is an Advanced Hunting table. All queries in this skill MUST use `RunAdvancedHuntingQuery`. Exception: Q5b (stale account enrichment via SigninLogs) may use Data Lake for 90d+ lookback.

2. **ALWAYS deduplicate accounts with `arg_max`** — The table contains multiple snapshots per account (state changes + 24h refresh). Every query that analyzes current account state MUST use `| summarize arg_max(Timestamp, *) by AccountId` to get the latest record per account.

3. **ASK the user for output format** before generating the report:
   - **Inline chat summary** (quick review in chat)
   - **Markdown file report** (detailed, archived to `reports/identity-posture/`)
   - **Both** (markdown + inline summary)

4. **⛔ MANDATORY: Evidence-based analysis only** — Report ONLY what query results show. Use the explicit absence pattern (`✅ No [finding] detected`) when queries return 0 results. Never guess or assume.

5. **Dynamic fields require `parse_json()` + `tostring()`** — `AssignedRoles`, `EligibleRoles`, `GroupMembership`, `Tags` are dynamic arrays. Always use `parse_json()` for `mv-expand` and `tostring()` for string comparisons.

6. **Run queries in parallel batches** where possible — Phase 1 queries (Q1–Q3) are independent. Phase 2 queries (Q4–Q8) are independent. Phase 3 (Q9–Q12) are independent.

7. **Time tracking** — Report elapsed time after each phase.

8. **Table is in Preview** — Some fields documented in the schema may not be populated yet (EnrolledMfas, TenantMembershipType, AuthenticationMethod, CriticalityLevel, DefenderRiskLevel). Handle gracefully — check for empty/null and report as "Not yet populated (Preview)" rather than "No data".

### ⛔ PROHIBITED ACTIONS

| Action | Status |
|--------|--------|
| Querying `IdentityAccountInfo` via `mcp_sentinel-data_query_lake` | ❌ **PROHIBITED** — AH-only table |
| Querying without `arg_max(Timestamp, *) by AccountId` deduplication | ❌ **PROHIBITED** — inflates counts |
| Reporting empty Preview fields as "No data found" | ❌ **PROHIBITED** — report as "Not yet populated (Preview)" |
| Filtering `AssignedRoles` or `Tags` with direct string comparison without `parse_json()` | ❌ **PROHIBITED** — dynamic fields |
| Assuming `SourceProviderRiskLevel` or `Tags` are populated for all providers | ❌ **PROHIBITED** — availability varies by IdP |

---

## Table Schema Reference

### IdentityAccountInfo (Primary)

| Column | Type | Description | Population |
|--------|------|-------------|------------|
| `Timestamp` | datetime | Snapshot timestamp (state change or 24h refresh) | ✅ All |
| `AccountId` | string | Internal account identifier (unique per provider account) | ✅ All |
| `IdentityId` | string | Unified identity — links accounts across providers | ✅ All |
| `AccountUpn` | string | User principal name | ✅ All |
| `DisplayName` | string | Display name | ✅ All |
| `SourceProvider` | string | Identity provider (AzureActiveDirectory, ActiveDirectory, Okta, SailPoint, CyberArkIdentity, Ping) | ✅ All |
| `AccountStatus` | string | Status (Enabled, Disabled, Deleted, ACTIVE, STAGED, DEPROVISIONED, etc.) | ✅ All |
| `Type` | string | Account type (User, ServiceAccount) | ✅ All |
| `AssignedRoles` | dynamic | Role assignments (AAD roles, CyberArk roles, etc.) | ✅ ~60% |
| `EligibleRoles` | dynamic | PIM-eligible roles | ❌ Empty (Preview) |
| `GroupMembership` | dynamic | Group IDs | ✅ ~72% |
| `Tags` | dynamic | MDI tags (Sensitive, Honeytoken, Privileged Account) | ✅ ~1% (tagged accounts only) |
| `SourceProviderRiskLevel` | dynamic | Risk level from source provider (Low/Medium/High/None) | ✅ ~18% (AAD + AD) |
| `LastPasswordChangeTime` | datetime | Last password change | 🟡 ~1% (sparse — mostly non-AAD) |
| `CreatedDateTime` | datetime | Account creation date | ✅ ~99% |
| `Department` | string | Department name | ✅ ~60% |
| `Manager` | string | Manager name | 🟡 ~1% |
| `City` / `Country` | string | Location | 🟡 <1% |
| `Sid` | string | Security Identifier (cloud SID for AAD, on-prem SID for AD) | ✅ ~89% |
| `IsPrimary` | bool | Whether this is the primary account for the linked identity | ✅ All |
| `IdentityLinkType` | string | Linkage type (Manual, StrongId) | ✅ All |
| `EnrolledMfas` | dynamic | MFA enrollment details | ❌ Empty (Preview) |
| `TenantMembershipType` | string | Guest/Member | ❌ Empty (Preview) |
| `AuthenticationMethod` | string | Credentials/Federated/Hybrid | ❌ Empty (Preview) |
| `CriticalityLevel` | int | Criticality score | ❌ Empty (Preview) |

### IdentityInfo (Enrichment — Join on IdentityId or AccountUpn)

Key columns used for enrichment:

| Column | Type | What It Adds |
|--------|------|-------------|
| `UserAccountControl` | dynamic | AD flags: PasswordNeverExpires, PasswordNotRequired, etc. |
| `DistinguishedName` | string | AD OU path |
| `RiskLevel` | string | Entra ID risk level (Low/Medium/High) |
| `BlastRadius` | string | UEBA blast radius (Low/Medium/High) — requires Sentinel UEBA |
| `PrivilegedEntraPimRoles` | dynamic | PIM role schedules (Preview — requires MDI) |
| `IsAccountEnabled` | boolean | Account enabled status |
| `RiskStatus` | string | None, AtRisk, Remediated, Dismissed, ConfirmedCompromised |

### IdentityLogonEvents (Enrichment — Join on AccountUpn)

Used for stale account detection (last logon across AD, Entra, third-party IdPs).

---

## Identity Posture Score Formula

The Identity Posture Score is a composite risk indicator summarizing the security posture of an organization's identity fabric. Higher scores indicate greater risk.

### Scoring Dimensions

$$
\text{IdentityPostureScore} = \sum_{i} \text{DimensionScore}_i
$$

Each dimension contributes 0–20 points to a maximum of 100:

| Dimension | Max | 🟢 Low (0–5) | 🟡 Medium (6–12) | 🔴 High (13–20) |
|-----------|-----|--------------|-------------------|------------------|
| **Stale/Deleted Account Risk** | 20 | <5% enabled accounts stale; 0 deleted with roles | 5–15% stale; <50 deleted with roles | >15% stale; >50 deleted accounts retaining roles |
| **Privileged Account Exposure** | 20 | <5 permanent high-priv accounts; all use PIM | 5–15 permanent high-priv; some PIM gaps | >15 permanent high-priv across multiple providers; no PIM |
| **Password Posture** | 20 | <10% PasswordNeverExpires; avg age <180d | 10–40% PwdNeverExpires; avg age 180–365d | >40% PwdNeverExpires; avg age >365d; PasswordNotRequired present |
| **Risk Distribution** | 20 | <5% accounts at High risk; all remediated/dismissed | 5–10% High risk; some unresolved | >10% High risk accounts active; unresolved AtRisk state |
| **Identity Sprawl** | 20 | <5% identities span >1 provider; consistent status | 5–15% multi-provider; some status mismatches | >15% multi-provider; status mismatches (enabled in one, disabled in another) |

### Interpretation Scale

| Score | Rating | Action |
|-------|--------|--------|
| **0–20** | ✅ Healthy | Normal posture, routine monitoring |
| **21–45** | 🟡 Elevated | Review — minor hygiene gaps detected |
| **46–70** | 🟠 Concerning | Investigate — multiple risk signals present |
| **71–100** | 🔴 Critical | Immediate remediation — significant identity security risk |

---

## Execution Workflow

### Phase 0: Prerequisites

1. Confirm `RunAdvancedHuntingQuery` is available (IdentityAccountInfo is AH-only)
2. Ask user for output format (inline / markdown / both)

### Phase 1: Inventory & Overview (Q1–Q3)

**Run in parallel — no dependencies between queries.**

| Query | Purpose | Table |
|-------|---------|-------|
| Q1 | Global inventory summary (accounts, identities, providers, date range) | IdentityAccountInfo |
| Q2 | Account status distribution by provider | IdentityAccountInfo |
| Q3 | Account type and department distribution | IdentityAccountInfo |

### Phase 2: Security Risk Analysis (Q4–Q8)

**Run in parallel — no dependencies between queries.**

| Query | Purpose | Tables |
|-------|---------|--------|
| Q4 | Privileged account audit — high-value roles across providers | IdentityAccountInfo |
| Q5 | Stale account detection — enabled with no logon in 90d | IdentityAccountInfo + IdentityLogonEvents |
| Q6 | Deleted account hygiene — deleted accounts retaining permissions | IdentityAccountInfo |
| Q7 | Password posture — age distribution + AD policy flags | IdentityAccountInfo + IdentityInfo |
| Q7c | Built-in & infrastructure account password audit | IdentityAccountInfo + IdentityInfo |
| Q8 | Multi-provider identity linking — cross-IdP sprawl and mismatches | IdentityAccountInfo |

### Phase 3: Risk & Governance (Q9–Q12)

**Run in parallel — no dependencies between queries.**

| Query | Purpose | Tables |
|-------|---------|--------|
| Q9 | Risk level distribution | IdentityAccountInfo |
| Q10 | MDI tags analysis (Sensitive, Honeytoken) | IdentityAccountInfo |
| Q11 | Service account inventory | IdentityAccountInfo |
| Q12 | Account creation trend | IdentityAccountInfo |

### Phase 4: Score Computation & Report Generation

1. **Compute per-dimension scores** from Phase 1–3 data
2. **Sum dimension scores** for composite Identity Posture Score
3. **Generate report** in requested output mode
4. **Report total elapsed time**

---

## Sample KQL Queries

> **All queries below are verified against the IdentityAccountInfo table schema (2026-03-24). Use them exactly as written, substituting only where noted.**

### Query 1: Global Inventory Summary

```kql
IdentityAccountInfo
| summarize 
    TotalRows = count(),
    UniqueAccounts = dcount(AccountId),
    UniqueIdentities = dcount(IdentityId),
    UniqueUPNs = dcount(AccountUpn),
    MinTimestamp = min(Timestamp),
    MaxTimestamp = max(Timestamp),
    SourceProviders = make_set(SourceProvider),
    AccountTypes = make_set(Type),
    AccountStatuses = make_set(AccountStatus)
```

### Query 2: Account Status Distribution by Provider

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| summarize Count = count() by SourceProvider, AccountStatus, Type
| order by Count desc
```

### Query 3: Department Distribution

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where isnotempty(Department)
| summarize Count = dcount(AccountId) by Department
| order by Count desc
| take 20
```

### Query 4: Privileged Account Audit

🔴 **Security-critical query** — identifies accounts with high-privilege roles across all identity providers.

```kql
let highPrivRoles = dynamic([
    "Global Administrator", "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "Application Administrator",
    "Cloud App Security Administrator", "Privileged Role Administrator",
    "Intune Administrator", "Compliance Administrator",
    "Privileged Authentication Administrator", "User Administrator",
    "Azure AD Joined Device Local Administrator",
    "SYSTEM_ADMINISTRATOR", "PRIVILEGE_CLOUD_ADMINISTRATORS",
    "PRIVILEGE_CLOUD_ADMINISTRATORS_LITE",
    "TDR_ADMINISTRATOR", "RISK_MANAGEMENT_ADMIN"
]);
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where AccountStatus in ("Enabled", "ACTIVE")
| where isnotempty(tostring(AssignedRoles)) and tostring(AssignedRoles) != "[]"
| mv-expand Role = parse_json(AssignedRoles)
| extend RoleName = tostring(Role)
| where RoleName in (highPrivRoles)
| summarize 
    HighPrivRoles = make_set(RoleName),
    RoleCount = dcount(RoleName)
    by AccountUpn, DisplayName, SourceProvider, AccountStatus
| order by RoleCount desc
```

**Post-processing:**
- Flag accounts with >2 high-privilege roles as excessive
- Cross-reference with Q8 (multi-provider) — accounts with high-priv roles in both AAD and CyberArk/AD represent dual-privilege risk
- Check if roles are permanent (currently `EligibleRoles` is empty in Preview, so all discovered roles appear permanent)
- Reference [MDI Assessment: Entra ID privileged users also privileged in AD](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts)
- **Pagination check:** If Q4 returns exactly 10,000 rows (AH limit), re-run with `| take 500` on the final output and note "Results may be truncated" in the report
- **Global Administrator callout:** After the high-priv table, always add a dedicated GA callout listing all accounts with the Global Administrator role. GA is the highest-risk role and should be immediately scannable

### Query 4b: Full Role Distribution

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where isnotempty(tostring(AssignedRoles)) and tostring(AssignedRoles) != "[]"
| mv-expand Role = parse_json(AssignedRoles)
| summarize AccountCount = dcount(AccountId) by tostring(Role)
| order by AccountCount desc
| take 25
```

### Query 5: Stale Account Detection

🔴 **Security-critical query** — identifies enabled accounts with no logon activity in 90 days.

```kql
let lastLogon = IdentityLogonEvents
| where Timestamp > ago(90d)
| summarize LastLogon = max(Timestamp) by AccountUpn;
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where AccountStatus in ("Enabled", "ACTIVE")
| join kind=leftouter (lastLogon) on AccountUpn
| where isnull(LastLogon) or LastLogon < ago(90d)
| summarize 
    StaleEnabledAccounts = count(),
    WithRoles = countif(isnotempty(tostring(AssignedRoles)) and tostring(AssignedRoles) != "[]"),
    WithGroups = countif(isnotempty(tostring(GroupMembership)) and tostring(GroupMembership) != "[]"),
    Providers = make_set(SourceProvider)
    by Type
| order by StaleEnabledAccounts desc
```

**Post-processing:**
- Stale accounts with active roles = **highest priority** for deprovisioning
- Reference [MDI Assessment: Remove stale Active Directory accounts](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts)
- Note: IdentityLogonEvents has 30d retention in AH. For accurate 90d stale detection, would need SigninLogs via Data Lake. The 30d window still catches accounts with zero recent activity

### Query 5b: Stale Account Provider Breakdown

```kql
let lastLogon = IdentityLogonEvents
| where Timestamp > ago(30d)
| summarize LastLogon = max(Timestamp) by AccountUpn;
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where AccountStatus in ("Enabled", "ACTIVE")
| join kind=leftouter (lastLogon) on AccountUpn
| where isnull(LastLogon)
| summarize StaleCount = count() by SourceProvider
| order by StaleCount desc
```

### Query 6: Deleted Account Hygiene

🟠 **Governance query** — identifies deleted accounts that still retain role assignments and group memberships.

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where AccountStatus == "Deleted"
| extend HasRoles = isnotempty(tostring(AssignedRoles)) and tostring(AssignedRoles) != "[]"
| extend HasGroups = isnotempty(tostring(GroupMembership)) and tostring(GroupMembership) != "[]"
| summarize 
    TotalDeleted = count(),
    DeletedWithRoles = countif(HasRoles),
    DeletedWithGroups = countif(HasGroups),
    DeletedWithBoth = countif(HasRoles and HasGroups),
    Providers = make_set(SourceProvider)
```

**Post-processing:**
- Deleted accounts with roles = orphan permission risk
- Note: in some providers, "Deleted" status may lag actual deletion. Cross-reference with `DeletedDateTime` if populated
- Large numbers indicate lifecycle management gaps

### Query 7: Password Posture (IdentityAccountInfo + IdentityInfo Join)

🟠 **Security query** — combines password age from IdentityAccountInfo with AD policy flags from IdentityInfo. Adapted from [Alex Verboon's MDI Password Security Posture Assessment](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/MDI-Identity-Password%20Security%20Posture%20Assessment.md) with critical fixes for join direction, null UAC handling, and epoch date filtering.

**Key design decisions:**
- **IdentityAccountInfo as primary (left) table** — using IdentityInfo as primary inflates row counts because IdentityInfo has multiple snapshots per identity. IdentityAccountInfo deduplicated by `IdentityId` gives the true enabled-account baseline.
- **Join on `IdentityId`** (not `AccountUpn`) — `IdentityId` is the stable cross-table key. UPN-based joins can produce 1:many inflation when multiple IdentityInfo records share a UPN.
- **`isnotnull(UserAccountControl)` guard on IdentityInfo** — see Pitfall #8 below. Without this, `array_index_of(null, "value")` returns `null`, and `null != -1` evaluates to `true` in KQL, making ALL null-UAC accounts appear to have PasswordNeverExpires.
- **`datetime(2000-01-01)` date guard** — some records contain placeholder dates (e.g., `0001-01-01`) producing 700,000+ day password ages.

```kql
let accountinfo = IdentityAccountInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IdentityId
| where AccountStatus !in ("Disabled", "Deleted", "DEPROVISIONED", "SUSPENDED")
| where Type != "ServiceAccount"
| extend DaysSinceLastPasswordChange =
    iff(isnull(LastPasswordChangeTime) or LastPasswordChangeTime < datetime(2000-01-01), int(null),
        datetime_diff('day', now(), LastPasswordChangeTime))
| extend Sensitive = array_index_of(Tags, "Sensitive") != -1
| project IdentityId, AccountUpn, AccountStatus, SourceProvider,
    LastPasswordChangeTime, DaysSinceLastPasswordChange, Sensitive;
let IdInfo = IdentityInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IdentityId
| where isnotnull(UserAccountControl)
| extend PasswordNeverExpires = array_index_of(UserAccountControl, "PasswordNeverExpires") != -1,
         PasswordNotRequired = array_index_of(UserAccountControl, "PasswordNotRequired") != -1
| project IdentityId, PasswordNeverExpires, PasswordNotRequired;
accountinfo
| join kind=leftouter (IdInfo) on IdentityId
| summarize
    TotalEnabled = count(),
    WithPasswordData = countif(isnotnull(DaysSinceLastPasswordChange)),
    AvgPasswordAgeDays = avgif(DaysSinceLastPasswordChange, isnotnull(DaysSinceLastPasswordChange)),
    MaxPasswordAgeDays = maxif(DaysSinceLastPasswordChange, isnotnull(DaysSinceLastPasswordChange)),
    PwdOver365d = countif(DaysSinceLastPasswordChange > 365),
    WithUACData = countif(isnotnull(PasswordNeverExpires)),
    PwdNeverExpires = countif(PasswordNeverExpires == true),
    PwdNotRequired = countif(PasswordNotRequired == true),
    SensitiveAccounts = countif(Sensitive)
```

**Post-processing:**
- `WithUACData` shows how many accounts had AD UAC flags to check — only on-prem AD accounts monitored by MDI will have this data
- `PwdNeverExpires` and `PwdNotRequired` are now **accurate counts** (not directional) thanks to the `isnotnull(UserAccountControl)` guard
- Report password data coverage: `WithPasswordData / TotalEnabled` — if < 5%, use condensed template

### Query 7b: Password Age Distribution Buckets (with PwdNeverExpires Cross-Reference)

```kql
let accountinfo = IdentityAccountInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IdentityId
| where isnotnull(LastPasswordChangeTime)
| where LastPasswordChangeTime > datetime(2000-01-01)
| where AccountStatus !in ("Disabled", "Deleted", "DEPROVISIONED", "SUSPENDED")
| where Type != "ServiceAccount"
| extend DaysSinceLastPasswordChange = datetime_diff('day', now(), LastPasswordChangeTime)
| project IdentityId, DaysSinceLastPasswordChange;
let IdInfo = IdentityInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IdentityId
| where isnotnull(UserAccountControl)
| extend PasswordNeverExpires = array_index_of(UserAccountControl, "PasswordNeverExpires") != -1
| project IdentityId, PasswordNeverExpires;
accountinfo
| join kind=leftouter (IdInfo) on IdentityId
| extend PasswordAgeBucket = case(
    DaysSinceLastPasswordChange <= 30, "0-30 days",
    DaysSinceLastPasswordChange <= 90, "31-90 days",
    DaysSinceLastPasswordChange <= 180, "91-180 days",
    DaysSinceLastPasswordChange <= 365, "181-365 days",
    "365+ days")
| summarize Accounts = count(), PwdNeverExpires = countif(PasswordNeverExpires == true) by PasswordAgeBucket
| order by Accounts desc
```

**Post-processing:**
- The `PwdNeverExpires` column per bucket reveals the root cause of stale passwords — if most 365+ day accounts have PwdNeverExpires, the issue is AD password policy, not user neglect
- Highlight correlation: "X of Y accounts with passwords >365 days old have PasswordNeverExpires set"

### Query 7c: Built-In & Infrastructure Account Password Check

🔴 **Security query** — audits password posture of built-in and infrastructure accounts (krbtgt, Administrator, Guest, MSOL_*, AAD_*, ADSync*). These accounts are high-value targets — krbtgt password age directly affects Golden Ticket attack risk.

```kql
let accountinfo = IdentityAccountInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IdentityId
| extend DaysSinceLastPasswordChange =
    iff(isnull(LastPasswordChangeTime) or LastPasswordChangeTime < datetime(2000-01-01), int(null),
        datetime_diff('day', now(), LastPasswordChangeTime))
| extend Sensitive = array_index_of(Tags, "Sensitive") != -1
| project IdentityId, AccountUpn, AccountStatus, SourceProvider,
    LastPasswordChangeTime, DaysSinceLastPasswordChange, Sensitive;
let IdInfo = IdentityInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IdentityId
| where isnotempty(AccountName)
| extend PasswordNeverExpires = iff(isnotnull(UserAccountControl), array_index_of(UserAccountControl, "PasswordNeverExpires") != -1, bool(null)),
         PasswordNotRequired = iff(isnotnull(UserAccountControl), array_index_of(UserAccountControl, "PasswordNotRequired") != -1, bool(null))
| extend OUPath = extract(@"CN=[^,]+,(.*)", 1, DistinguishedName)
| project IdentityId, AccountName, AccountDomain, AccountDisplayName,
    PasswordNeverExpires, PasswordNotRequired, OUPath;
IdInfo
| join kind=leftouter (accountinfo) on IdentityId
| where tolower(AccountName) in ("krbtgt", "administrator", "guest", "admin")
    or tolower(AccountName) startswith "msol_"
    or tolower(AccountName) startswith "aad_"
    or tolower(AccountName) startswith "adsync"
| project AccountName, AccountDomain, AccountDisplayName, AccountStatus,
    SourceProvider, LastPasswordChangeTime, DaysSinceLastPasswordChange,
    PasswordNeverExpires, PasswordNotRequired, Sensitive, OUPath
| order by DaysSinceLastPasswordChange desc
```

**Post-processing:**
- **krbtgt:** Microsoft recommends rotation every 180 days. Flag any krbtgt account with password >180d as 🔴 High Risk (Golden Ticket attack window). >365d is critical
- **MSOL_/AAD_/ADSync:** Azure AD Connect service accounts. If `AccountStatus == "Enabled"` but the sync is decommissioned, flag as 🟠 stale privileged account. PwdNeverExpires is common but should be monitored
- **Guest:** PwdNotRequired is standard Windows behavior for Guest accounts. Flag only if Guest is Enabled (should always be Disabled)
- **Administrator:** Check if renamed (may not appear). Flag if password >365d

### Query 8: Multi-Provider Identity Linking

🟡 **Governance query** — identifies identities that span multiple identity providers, including status mismatches.

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| summarize 
    Providers = make_set(SourceProvider),
    ProviderCount = dcount(SourceProvider),
    Statuses = make_set(AccountStatus),
    StatusCount = dcount(AccountStatus),
    UPNs = make_set(AccountUpn),
    RolesSummary = make_set(tostring(AssignedRoles))
    by IdentityId
| where ProviderCount > 1
| extend HasStatusMismatch = StatusCount > 1
| summarize 
    MultiProviderIdentities = count(),
    WithStatusMismatch = countif(HasStatusMismatch),
    MaxProviders = max(ProviderCount),
    ProviderCombos = make_set(strcat_array(Providers, " + "))
```

### Query 8b: Multi-Provider Identity Detail (Top 15)

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| summarize 
    Providers = make_set(SourceProvider),
    ProviderCount = dcount(SourceProvider),
    Statuses = make_set(AccountStatus),
    UPNs = make_set(AccountUpn),
    Roles = make_set(tostring(AssignedRoles))
    by IdentityId, DisplayName
| where ProviderCount > 1
| order by ProviderCount desc
| take 15
```

### Query 9: Risk Level Distribution

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where isnotempty(tostring(SourceProviderRiskLevel))
| summarize 
    Count = dcount(AccountId),
    EnabledCount = dcountif(AccountId, AccountStatus in ("Enabled", "ACTIVE")),
    WithHighPrivRoles = dcountif(AccountId, isnotempty(tostring(AssignedRoles)) and tostring(AssignedRoles) != "[]")
    by tostring(SourceProviderRiskLevel), SourceProvider
| order by Count desc
```

**Post-processing:**
- High-risk accounts that are Enabled + have high-priv roles = **critical finding**
- Cross-reference with IdentityInfo `RiskStatus` for Entra accounts to check if risk has been remediated/dismissed

### Query 10: MDI Tags Analysis

🏷️ **Governance query** — analyzes Defender for Identity tags (Sensitive, Honeytoken, custom tags).

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where isnotempty(tostring(Tags)) and tostring(Tags) != "[]"
| mv-expand Tag = parse_json(Tags)
| extend TagName = tostring(Tag)
| summarize 
    AccountCount = dcount(AccountId),
    Accounts = make_set(AccountUpn, 10)
    by TagName, SourceProvider
| order by AccountCount desc
```

**Post-processing:**
- Sensitive-tagged accounts should be cross-referenced with Q4 (privileged) and Q9 (risk) for comprehensive posture view
- Honeytoken accounts — verify monitoring is active (any logon should generate an alert)

### Query 11: Service Account Inventory

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where Type == "ServiceAccount"
| summarize 
    Count = count(),
    Providers = make_set(SourceProvider),
    Statuses = make_set(AccountStatus),
    EnabledCount = countif(AccountStatus in ("Enabled", "ACTIVE")),
    WithRoles = countif(isnotempty(tostring(AssignedRoles)) and tostring(AssignedRoles) != "[]")
```

### Query 12: Account Creation Trend

📈 **Trend query** — shows account creation velocity over time.

```kql
IdentityAccountInfo
| summarize arg_max(Timestamp, *) by AccountId
| where isnotempty(CreatedDateTime)
| summarize AccountsCreated = count() by bin(CreatedDateTime, 7d), SourceProvider
| order by CreatedDateTime asc
```

---

## Output Modes

### Mode 1: Inline Chat Summary

Render the full analysis directly in the chat response. Best for quick review.

### Mode 2: Markdown File Report

Save a comprehensive report to disk at:
```
reports/identity-posture/Identity_Posture_Report_{tenant}_YYYYMMDD_HHMMSS.md
```

Where `{tenant}` is a short identifier for the tenant (e.g., `contoso`, `zava`). Derive from the tenant domain in `config.json` or ask the user. If unknown, omit the tenant tag.

### Mode 3: Both

Generate the markdown file AND provide an inline summary in chat.

**Always ask the user which mode before generating output.**

---

## Inline Report Template

Render the following sections in order. Omit sections only if explicitly noted as conditional.

> **🔴 URL Rule:** All hyperlinks in the report MUST be copied verbatim from the [URL Registry](#-url-registry--canonical-links-for-report-generation) above. Do NOT generate, recall from memory, or paraphrase any URL. If a needed URL is not in the registry, use plain text (no hyperlink).

````markdown
# 🔐 Identity Security Posture Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Data Source:** IdentityAccountInfo (Advanced Hunting — Preview)
**Analysis Period:** <EarliestRecord> → <LatestRecord>
**Identity Providers:** <comma-separated provider list>

---

## Executive Summary

<2-3 sentences: total accounts/identities, key risk findings, overall score>

**Overall Risk Rating:** 🔴/🟠/🟡/✅ <RATING> (<Score>/100)

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Total Accounts (deduplicated) | <N> |
| Unique Identities | <N> |
| Identity Providers | <N> (<list>) |
| Enabled Accounts | <N> |
| Disabled Accounts | <N> |
| Deleted Accounts | <N> |
| Service Accounts | <N> |
| Accounts with High-Privilege Roles | <N> |
| Stale Accounts (no logon 30d*) | <N> |
| Multi-Provider Identities | <N> |
| MDI Sensitive-Tagged Accounts | <N> |

> \* IdentityLogonEvents has 30-day retention in Advanced Hunting. True 90-day stale count is lower. See Stale & Deleted Account Hygiene section for details.

---

## 🔍 Identity Inventory

### Accounts by Provider
| Provider | Accounts | Enabled | Disabled | Deleted | Other | Service Accounts |
|----------|----------|---------|----------|---------|-------|------------------|
| <provider> | <N> | <N> | <N> | <N> | <N> | <N> |
| **Total** | **<N>** | **<N>** | **<N>** | **<N>** | **<N>** | **<N>** |

> **Account count note:** The provider breakdown may sum to slightly more than the deduplicated "Total Accounts" in Key Metrics because `arg_max(Timestamp, *) by AccountId` resolves each account to a single snapshot, while a small number of AccountIds may share provider rows. Always use the deduplicated count from Q1 as the authoritative total.

### Account Status Vocabulary by Provider

| Status | Meaning | Providers |
|--------|---------|----------|
| Enabled / ACTIVE | Active account | AAD, AD, SailPoint, CyberArk, Okta, Ping |
| Disabled | Administratively disabled | AAD, AD |
| Deleted | Soft-deleted (AAD recycle bin) | AAD |
| NONE | No status (SailPoint) | SailPoint |
| INACTIVE | Deactivated | SailPoint |
| STAGED | Provisioned but not activated | Okta |
| DEPROVISIONED | Fully deactivated | Okta |
| PROVISIONED | Created but pending activation | Okta |
| INVITED | Pending acceptance | CyberArk |
| CREATED | Newly created | CyberArk |
| SUSPENDED | Temporarily suspended | CyberArk |

> Include this table in every report. Values are discovered dynamically from Q2 output — add any new statuses observed.

### Department Distribution (Top 15)
| Department | Accounts |
|------------|----------|
| <dept> | <N> |

> **Department aggregation rule:** When case-inconsistent values exist (e.g., "Internal" vs "internal"), collapse them into a single row with combined count and note the inconsistency: `> ⚠️ Department values have case inconsistency: "Internal" (N) and "internal" (N) appear as separate values. Recommend standardizing.`

---

## 👑 Privileged Account Audit

### High-Privilege Role Holders
| Account | Provider | Roles | Status |
|---------|----------|-------|--------|
| <upn> | <provider> | <role list> | <status> |

> 🔴 **Global Administrators (<N>):** <comma-separated list of GA account UPNs> — Best practice: max 2 permanent GA accounts (break glass only). Convert user-facing GA accounts to PIM-eligible.

### Role Distribution (Top 15)
| Role | Account Count |
|------|---------------|
| <role> | <N> |

**Assessment:**
- <emoji> <evidence-based finding about privilege distribution>
- <emoji> <PIM/permanent role finding>
- <emoji> <cross-provider privilege finding>

---

## 🗑️ Stale & Deleted Account Hygiene

### Stale Accounts (Enabled, No Logon in 30d)
| Metric | Value |
|--------|-------|
| Total Stale Enabled | <N> |
| Stale with Active Roles | <N> |
| Stale with Group Memberships | <N> |
| Stale by Provider | <breakdown> |

> ⚠️ **Important caveat:** IdentityLogonEvents has **30-day retention** in Advanced Hunting. Accounts that last logged in 31–90 days ago appear "stale" in this analysis. The true 90-day stale count is likely lower. For accurate 90-day stale detection, cross-reference with SigninLogs via Data Lake (90d+ retention).

### Deleted Accounts with Residual Permissions
| Metric | Value |
|--------|-------|
| Total Deleted | <N> |
| Deleted with Roles | <N> |
| Deleted with Groups | <N> |
| Deleted with Both | <N> |

**Assessment:**
- <emoji> <evidence-based finding about stale account risk>
- <emoji> <deleted account orphan risk finding>

---

## 🔑 Password Posture

<If LastPasswordChangeTime coverage ≥ 5% of enabled accounts — render full section:>
| Metric | Value |
|--------|-------|
| Accounts with Password Data | <WithPasswordData>/<TotalEnabled> (<pct>%) |
| Accounts with UAC Data | <WithUACData> |
| PasswordNeverExpires | <N> of <WithUACData> with UAC data |
| PasswordNotRequired | <N> of <WithUACData> with UAC data |
| Sensitive Accounts | <N> |
| Avg Password Age (days) | <N> |
| Max Password Age (days) | <N> |
| Passwords > 365 days | <PwdOver365d> |

### Password Age Distribution
| Bucket | Accounts | PwdNeverExpires | % |
|--------|----------|-----------------|---|
| 0-30 days | <N> | <N> | <pct>% |
| 31-90 days | <N> | <N> | <pct>% |
| 91-180 days | <N> | <N> | <pct>% |
| 181-365 days | <N> | <N> | <pct>% |
| 365+ days | <N> | <N> | <pct>% |

<Highlight if PwdNeverExpires correlates with 365+ bucket:>
> 🔴 **X of Y accounts with passwords >365 days old have PasswordNeverExpires set** — these passwords will never rotate without manual intervention.

<If LastPasswordChangeTime coverage < 5% of enabled accounts — render condensed format instead:>
⚠️ **Limited data availability:** `LastPasswordChangeTime` populated for <N>/<TotalEnabled> enabled accounts (<pct>%).
Among accounts with data: <N> have passwords >365d old, <N> changed within 30d.
For comprehensive assessment, use Graph API (`/users?$select=passwordPolicies,lastPasswordChangeDateTime`).

### AD Password Policy Flags (via IdentityInfo UAC enrichment)
| Flag | Accounts | Scope |
|------|----------|-------|
| PasswordNeverExpires | <N> | <WithUACData> accounts with UAC data (on-prem AD with MDI only) |
| PasswordNotRequired | <N> | <WithUACData> accounts with UAC data |

> **Data quality note:** UAC flags are only available for on-prem AD accounts monitored by MDI (~<WithUACData>/<TotalEnabled> accounts in this environment). The `isnotnull(UserAccountControl)` filter ensures accurate counts — no inflation from null-UAC accounts.

### Built-In & Infrastructure Account Password Audit

<Render from Q7c results. Always include this section — built-in accounts exist in every AD environment.>

| Account | Domain | Status | Password Age | PwdNeverExpires | PwdNotRequired | Sensitive |
|---------|--------|--------|-------------|----------------|----------------|----------|
| <AccountName> | <AccountDomain> | <Status> | <DaysSinceLastPasswordChange>d | <Yes/No> | <Yes/No> | <Yes/No> |

<Flag critical findings:>
- 🔴 **krbtgt** accounts with password >180 days — Golden Ticket attack window (Microsoft recommends 180-day rotation)
- 🟠 **MSOL_/AAD_/ADSync** accounts still Enabled with PwdNeverExpires — review if Azure AD Connect is still in use
- 🟡 **Guest** accounts with PwdNotRequired — standard Windows behavior, flag only if Enabled

---

## 🟠 Risk Distribution

| Risk Level | Provider | Total | Enabled | With High-Priv Roles |
|------------|----------|-------|---------|----------------------|
| 🔴 High | <provider> | <N> | <N> | <N> |
| 🟠 Medium | <provider> | <N> | <N> | <N> |
| 🟡 Low | <provider> | <N> | <N> | <N> |
| ⚪ None | <provider> | <N> | <N> | <N> |

**Assessment:**
- <emoji> <evidence-based finding about active high-risk accounts>

---

## 🔗 Multi-Provider Identity Linking

| Metric | Value |
|--------|-------|
| Identities Spanning Multiple Providers | <N> |
| Max Providers per Identity | <N> |
| Identities with Status Mismatches | <N> |
| Provider Combinations | <list> |

<If status mismatches found:>
⚠️ **Status Mismatches Detected:** <N> identities have inconsistent status across providers (e.g., Enabled in AAD but DEPROVISIONED in Okta). This indicates lifecycle management gaps.

<Top 5 multi-provider identities table>

---

## 🏷️ Sensitive & Honeytoken Accounts

| Tag | Count | Provider | Sample Accounts |
|-----|-------|----------|----------------|
| <tag> | <N> | <provider> | <upn list> |

**Assessment:**
- <emoji> <honeytoken monitoring confirmation>
- <emoji> <sensitive account protection finding>

---

## Identity Posture Score Card

```
┌─────────────────────────────────────────────────────────────┐
│          IDENTITY POSTURE SCORE: <NN>/100                   │
│                Rating: <EMOJI> <RATING>                     │
├─────────────────────────────────────────────────────────────┤
│ Stale/Deleted  [<bar>] <N>/20  (<short detail>)             │
│ Privileged     [<bar>] <N>/20  (<short detail>)             │
│ Password       [<bar>] <N>/20  (<short detail>)             │
│ Risk Distrib.  [<bar>] <N>/20  (<short detail>)             │
│ Identity Sprawl[<bar>] <N>/20  (<short detail>)             │
└─────────────────────────────────────────────────────────────┘
```

> **Score card detail rule:** Keep `(<short detail>)` to ~30 characters max so text fits within the box. Use abbreviated phrasing, e.g., `885 deleted w/roles; high stale %` not `885 deleted accounts with active role assignments`.

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| <emoji> **<Factor>** | <Evidence-based finding> |

---

## Recommendations

1. <emoji> **<Priority action>** — <evidence and rationale>
2. ...

---

## Next Steps

<1-2 sentences anchoring the immediate follow-up action based on the highest-priority recommendation. Reference the specific recommendation number.>

Example:
> Begin with Recommendation #1 (High-Risk account remediation) by exporting the 560 affected accounts to the security operations team. Schedule a follow-up identity posture review after remediation to verify score improvement.

---

## Appendix: Query Execution Summary

| Query | Description | Records | Time |
|-------|-------------|---------|------|
| Q1 | Global Inventory | <N> | <time> |
| Q2 | Status by Provider | <N> | <time> |
| ... | ... | ... | ... |
````

---

## Markdown File Report Template

When outputting to markdown file, use the same structure as the Inline Report Template above, saved to:

```
reports/identity-posture/Identity_Posture_Report_{tenant}_YYYYMMDD_HHMMSS.md
```

Where `{tenant}` matches the Mode 2 filename convention above.

Include the following additional sections in the file report that are omitted from inline:

1. **Full privileged account detail table** (all high-priv accounts, not just top N)
2. **Complete multi-provider identity listing** (all multi-IdP identities with UPN mapping)
3. **Per-provider account detail** (full status/type breakdown per provider)
4. **Stale account detail** (top stale accounts with last logon dates)
5. **Preview field coverage summary** (which documented fields are/aren't populated)

### File Report Header

```markdown
# Identity Security Posture Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Data Source:** IdentityAccountInfo (Advanced Hunting — Preview)
**Enrichment:** IdentityInfo, IdentityLogonEvents
**Analysis Period:** <EarliestRecord> → <LatestRecord> (<N> days)
**Identity Providers:** <N> (<list with account counts>)
**Total Accounts:** <N> (Enabled/Active: ~<N> | Disabled: ~<N> | Deleted: <N> | Other: ~<N>)
**Unique Identities:** <N>

---
```

> **Account count convention:** Use the deduplicated count from Q1 (`dcount(AccountId)`) as the authoritative "Total Accounts". Provider breakdowns from Q2 may sum slightly higher due to snapshot resolution. Present status sub-counts with `~` prefix when derived from Q2 provider rows to signal they are approximate breakdowns.

---

## SVG Dashboard Generation

> 📊 **Optional post-report step.** After an Identity Security Posture report is generated, the user can request a visual SVG dashboard.

**Trigger phrases:** "generate SVG dashboard", "create a visual dashboard", "visualize this report", "SVG from the report"

### How to Request a Dashboard

- **Same chat:** "Generate an SVG dashboard from the report" — data is already in context.
- **New chat:** Attach or reference the report file, e.g. `#file:reports/identity-posture/Identity_Posture_Report_<tenant>_<date>.md`
- **Customization:** Edit [svg-widgets.yaml](svg-widgets.yaml) before requesting — the renderer reads it at generation time.

### Execution

```
Step 1:  Read svg-widgets.yaml (this skill's widget manifest)
Step 2:  Read .github/skills/svg-dashboard/SKILL.md (rendering rules — Manifest Mode)
Step 3:  Read the completed report file (data source)
Step 4:  Render SVG → save to reports/identity-posture/{report_name}_dashboard.svg
```

The YAML manifest is the single source of truth for layout, widgets, field mappings, colors, and data source documentation. All customization happens there.

---

## Known Pitfalls

### 1. IdentityAccountInfo Is Advanced Hunting Only

**Problem:** The table does NOT exist in Sentinel Data Lake. Querying via `mcp_sentinel-data_query_lake` returns `SemanticError: Failed to resolve table`.

**Solution:** Always use `RunAdvancedHuntingQuery`. The table has 30-day retention in AH.

### 2. Multiple Records Per Account (State Snapshots)

**Problem:** The table logs configuration snapshots over time (state changes + 24h refresh). Querying without deduplication inflates counts.

**Solution:** Always use `| summarize arg_max(Timestamp, *) by AccountId` for current state analysis. Use `by IdentityId` when you want the latest per unified identity.

### 3. AccountStatus Values Are Provider-Specific

**Problem:** Each identity provider uses its own status vocabulary:
- AAD: `Enabled`, `Disabled`, `Deleted`
- SailPoint: `ACTIVE`, `NONE`, `INACTIVE`
- Okta: `STAGED`, `ACTIVE`, `DEPROVISIONED`, `PROVISIONED`
- CyberArk: `ACTIVE`, `INVITED`, `SUSPENDED`, `CREATED`

**Solution:** When filtering for "active/enabled" accounts, use `AccountStatus in ("Enabled", "ACTIVE")` to catch both AAD and third-party providers. For "disabled" filtering, include provider-specific disabled states.

### 4. AssignedRoles Contains Mixed Role Vocabularies

**Problem:** `AssignedRoles` contains role names from different providers in the same column — AAD roles ("Global Administrator"), CyberArk roles ("SYSTEM_ADMINISTRATOR"), Okta roles, etc. They are NOT normalized.

**Solution:** When searching for high-privilege roles, include role names from all providers in the `highPrivRoles` list. See Q4 for the canonical list.

### 5. EligibleRoles Is Empty (Preview)

**Problem:** The `EligibleRoles` column (for PIM-eligible roles) is documented but currently returns empty for all accounts.

**Impact:** Cannot distinguish permanent vs PIM-eligible roles from this table alone. All discovered roles in `AssignedRoles` should be treated as potentially permanent. For accurate PIM data, use Graph API (`/roleManagement/directory/roleEligibilityScheduleInstances`).

### 6. EnrolledMfas/TenantMembershipType/AuthenticationMethod Are Empty

**Problem:** These fields are documented but not yet populated in any provider. This is expected for a Preview table.

**Solution:** Report as "Not yet populated (Preview)" — not as absence of MFA or guest accounts. For MFA data, use SigninLogs (`AuthenticationDetails`) or Graph API. For Guest/Member, use IdentityInfo (`TenantMembershipType` — same issue) or Graph API.

### 7. LastPasswordChangeTime Is Sparse for AAD

**Problem:** Only ~1% of accounts have `LastPasswordChangeTime` populated, mostly non-AAD providers (CyberArk, Okta). AAD accounts typically show null. Some records contain placeholder dates (e.g., `0001-01-01T00:00:00Z`) that produce nonsensical password age values (700,000+ days).

**Solution:** For AD-specific password posture, join with `IdentityInfo` which has `UserAccountControl` flags (PasswordNeverExpires, PasswordNotRequired). For cloud-only AAD, password age data may need Graph API enrichment. Always filter `where LastPasswordChangeTime > datetime(2000-01-01)` to exclude placeholder dates before computing avg/max.

### 8. `array_index_of(null)` Returns Null — Not `-1`

**Problem:** When `UserAccountControl` is null (which it is for ~99% of identities in IdentityInfo — only on-prem AD accounts with MDI have it), `array_index_of(null, "PasswordNeverExpires")` returns **`null`** — NOT `-1`. In KQL, `null != -1` evaluates to **`true`**. This means Verboon's original pattern `array_index_of(UserAccountControl, "PasswordNeverExpires") != -1` incorrectly returns `true` for ALL accounts with null UserAccountControl, massively inflating PwdNeverExpires counts (e.g., 16,197 false positives out of 16,297 identities).

**Solution:** In the IdentityInfo `let` block, add `| where isnotnull(UserAccountControl)` BEFORE computing the boolean flags. This limits the UAC analysis to accounts that actually have UAC data (~100 out of 16,000+ in a typical environment). The Q7 query uses `leftouter` join, so accounts without UAC data get null for the flag columns, and `countif(PasswordNeverExpires == true)` correctly excludes nulls. Counts from this pattern are now **accurate**, not directional.

### 8b. Q7 IdentityInfo Join — Use `IdentityId`, Not `AccountUpn`

**Problem:** Joining on `AccountUpn` can produce 1:many inflation when multiple IdentityInfo records share the same UPN. Additionally, using IdentityInfo as the primary (left) table inflates the row count because IdentityInfo contains multiple snapshot records per identity.

**Solution:** Use `IdentityAccountInfo` as the primary table (deduplicated by `IdentityId`). Join IdentityInfo on `IdentityId` (the stable cross-table identity key). Deduplicate IdentityInfo by `IdentityId` as well. This ensures 1:1 matching and the correct enabled-account baseline.

### 9. Tags Only Available on Accounts with MDI Coverage

**Problem:** `Tags` (Sensitive, Honeytoken, etc.) are populated only by Defender for Identity. Accounts from providers without MDI integration won't have tags.

**Solution:** Don't interpret "no tags" as "not sensitive." Report the count of tagged accounts and note that only MDI-monitored accounts can be tagged.

### 10. IdentityLogonEvents Has 30-Day Retention in AH

**Problem:** When using IdentityLogonEvents for stale account detection (Q5), AH only retains 30 days. Accounts that last logged in 31–90 days ago will appear "stale" if only checking IdentityLogonEvents.

**Solution:** For accurate 90-day stale detection, consider enriching with SigninLogs via Data Lake (90d+ retention). The 30d IdentityLogonEvents window is still useful for identifying accounts with zero recent activity.

### 11. Deduplication Key: AccountId vs IdentityId

**Problem:** `AccountId` is unique per provider-account pair. `IdentityId` is the unified identity (one person may have multiple AccountIds). Using the wrong key inflates or deflates counts.

**Solution:**
- Use `by AccountId` when counting individual accounts/provider-specific analysis
- Use `by IdentityId` when counting people/unified identity analysis
- Q7 (password posture) uses `by IdentityId` because it joins with IdentityInfo per person
- Q8 (multi-provider) groups by IdentityId to detect cross-provider linking

### 12. SourceProviderRiskLevel vs IdentityInfo.RiskLevel

**Problem:** Both tables have risk level fields but they may differ:
- `IdentityAccountInfo.SourceProviderRiskLevel`: Risk from the source provider (AAD Identity Protection, AD MDI)
- `IdentityInfo.RiskLevel`: Entra ID risk level + `RiskStatus` for remediation state

**Solution:** For a complete risk picture, check both. `SourceProviderRiskLevel` covers more providers; `IdentityInfo.RiskLevel` + `RiskStatus` gives Entra-specific remediation context.

### 13. Provider Count Varies by Tenant

**Problem:** Not all tenants have 6 providers connected. The provider list depends on which identity sources are integrated with Defender XDR / MDI.

**Solution:** Always report the actual providers found rather than assuming a fixed set. The inventory query (Q1) discovers this dynamically.

---

## Quality Checklist

Before delivering the report, verify:

- [ ] All queries used `arg_max(Timestamp, *) by AccountId` (or `by IdentityId` where noted)
- [ ] All queries ran via `RunAdvancedHuntingQuery` (not Data Lake, except Q5b enrichment)
- [ ] Zero-result queries reported with explicit absence confirmation (✅ pattern)
- [ ] Identity Posture Score computation is transparent with per-dimension evidence
- [ ] AccountStatus filtering handles provider-specific vocabularies
- [ ] Privileged account audit includes roles from all providers (AAD + CyberArk + Okta)
- [ ] Empty Preview fields reported as "Not yet populated (Preview)" not "No data"
- [ ] Password posture correctly notes LastPasswordChangeTime sparsity
- [ ] Multi-provider identity analysis includes status mismatch detection
- [ ] Recommendations are prioritized and evidence-based
- [ ] All hyperlinks copied verbatim from URL Registry
- [ ] No PII from live environments in the SKILL.md file itself
