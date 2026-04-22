# <Your Tenant Name> — Investigation Context

> **Template file** — copy to `<your-tenant-shortname>.md` and fill in the placeholders for your environment. Then run `.\scripts\sync-repo-memory.ps1` to push it into Copilot's repo memory.

**At a glance:** Tenant identifiers · Known infrastructure IPs · Service account naming · Known false-positive patterns · Validated personnel · Lessons learned

**Purpose:** Captures tenant-specific facts that don't change often but burn investigation time when re-discovered (orchestration IPs misclassified as attackers, service accounts flagged as compromised, scheduled tasks treated as anomalies, vendor agents triggering generic detections).

**⚠️ PII / sensitivity:** Repo memory is NOT in git (gitignored via `notes/`). Treat this file as **internal-only**. Do not paste into public channels, screenshots, or AI chats outside your tenant.

---

## Tenant Identifiers

- **Tenant ID:** `<your-tenant-guid>`
- **Sentinel workspace:** `<workspace-name>` (`<workspace-guid>`)
- **Primary domain:** `<yourcompany.com>`
- **Secondary / acquisition domains:** `<list any merged tenants>`
- **Defender XDR portal:** `https://security.microsoft.com/?tid=<your-tenant-guid>`

---

## Known Infrastructure IPs

Document IPs that look suspicious to detection rules but are actually trusted infrastructure. Saves re-triage on every investigation that touches them.

| IP / CIDR | Owner | Purpose | Common FP triggers |
|---|---|---|---|
| `<x.x.x.0/24>` | Corp NAT egress | All workstation outbound — high sign-in volume normal | `unfamiliarTenantIPsubnet` for new hires |
| `<y.y.y.y>` | Vuln scanner (e.g., Qualys, Tenable, Rapid7) | Authenticated scans against domain controllers | `T1110 Brute force`, `unusual logon time` |
| `<z.z.z.z>` | Backup service (e.g., Veeam, Azure Backup) | Triggers AuditLogs admin role activations weekly | `Privileged role assignment outside business hours` |
| `<a.a.a.0/24>` | VDI / Cloud PC range | Shared by N analysts; per-user device fingerprint differs | `unfamiliarBrowser`, `unfamiliarDevice`, `unfamiliarEASId`, `unlikelyTravel` |
| `<b.b.b.b>` | SOC jump-host | Analysts pivot through this for incident response | `unfamiliarLocation` if hosted in different region than analyst |

**Recommended action:** Add the trusted ranges to **Entra Named Locations** as `Trusted: <name>` and apply Conditional Access exclusions where appropriate. Document any exclusions here so future investigators don't think they're a misconfiguration.

---

## Service Account Naming Patterns

Helps Copilot classify accounts without re-checking each one:

- `svc-*@yourcompany.com` — service accounts; expect non-interactive sign-ins from app servers, no MFA
- `adm-*@yourcompany.com` — admin tier; should always be PIM-eligible, never permanent
- `*_jit@yourcompany.com` — JIT break-glass; alert if active > 4hr
- `<other patterns specific to your org>`

**Naming anti-patterns to flag:** Accounts that don't match any pattern above but have privileged role assignments — these are the candidates for legacy admin cleanup.

---

## Known False-Positive Patterns

Document detections that fire reliably for benign reasons. Without this, every investigation re-discovers them.

### Vendor agents
- **`<Vendor X> agent process`** triggers `T1059.001 PowerShell encoded command` daily — legitimate; signed by `<publisher>`. Filter: `InitiatingProcessSignerType == "ValidSignature" and InitiatingProcessSignatureStatus == "Valid"`
- **`<EDR/Backup vendor> service`** triggers `T1003 LSASS access` — required for credential vaulting; filter by `InitiatingProcessFileName`

### Conditional Access policies
- **CA policy `<name>`** is intentionally **report-only** for testing — do NOT recommend enforcing without checking with `<owner>` first
- **CA policy `<name>`** excludes `<group>` for legitimate business reasons — do NOT flag the exclusion as a gap

### Scheduled tasks
- Daily `<HH:MM UTC>` AzureActivity spike from `<service>` doing `<operation>` — expected, not exfil

### Detection rules
- Rule `<name>` is known noisy for `<reason>` — pending tune; ignore if entity is `<X>`

---

## Validated Personnel (high-context investigations)

When investigating these accounts, Copilot should know they are real, identified humans whose unusual activity has business justification. Do not deanonymize or expose this list publicly.

- `<UPN>` — Security Director; expected to access SecOps tools daily, run unusual KQL, view mailbox content during investigations
- `<UPN>` — Threat hunter; expected to run rare/expensive queries
- `<UPN>` — IT operations; expected to run admin scripts on weekends

**For any account NOT on this list:** Default to standard investigation depth — do not assume legitimacy.

---

## Lessons Learned

Append-only log of investigation outcomes. Each entry is one line: date, pattern, verdict, why.

- 2026-MM-DD: `<one-line description of pattern + verdict + reason>`
- 2026-MM-DD: `<one-line description of pattern + verdict + reason>`

**Why this section matters:** Every "I've seen this before" moment that didn't get written down costs you the next analyst's hour to re-investigate. Add an entry whenever you close an investigation with a non-obvious conclusion.
