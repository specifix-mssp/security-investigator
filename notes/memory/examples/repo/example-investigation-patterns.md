# Investigation Patterns — Generic Reminders

> **Generic, tenant-agnostic patterns** that improve every investigation. Safe to share publicly. Customize, extend, or trim to your team's playbook.

These are pattern-of-thought reminders that help Copilot avoid the most common analyst mistakes. They sit in repo memory because they apply to *every* investigation, not just one entity.

---

## When investigating a suspicious IP, ALWAYS:

1. **Hunt the IP across the whole tenant first** — not just the one user/device that flagged it. Multi-user activity = shared infrastructure (VPN, proxy, Cloud PC, jump-host), NOT a targeted attack. Single-user activity from a residential ISP in an unexpected geo = much higher signal.
2. **Check against known corporate egress ranges** before paying for 3rd-party enrichment. NAT IPs always look "high volume" because they aggregate hundreds of users.
3. **If 3rd-party enrichment flags VPN/Tor**, check whether your org *allows* VPN. Many do for remote workers — VPN ≠ malicious by itself.
4. **Cross-reference with Entra Named Locations** in CA policies. If the IP is already classified as Trusted, the original detection was likely tuned wrong.
5. **Beware Azure datacenter IPs** flagged as TITAN BruteForce — frequent false positive on legitimate cloud-hosted services (Microsoft's own, partners', or your own Azure resources).

---

## When a service principal shows behavioral drift, ALWAYS:

1. **Check whether the SPN owner is on PTO, changed roles, or left the company** — legitimate scope expansion happens when responsibilities transfer.
2. **Look for credential add events in AuditLogs** in the same 7-day window. New secret/cert + drift in API calls = compromised SPN. New secret/cert + no API change = likely rotation.
3. **Compare granted permissions vs actual API calls.** Over-privileged is not the same as abused. Reduce permissions during a separate hardening exercise; investigate only if calls exceed grants.
4. **Check the SPN's sign-in IP history.** Drift to a new tenant ID, new geo, or new ASN = high signal. Same Azure region as the resources it manages = expected.

---

## When MFA fatigue (T1621) detection fires, ALWAYS:

1. **Check sign-in geo + UA** for the attempts that prompted the push. Unusual geo + impossible travel = real attack. Same geo as user's normal pattern + Authenticator app reset = false positive.
2. **Check whether the user reported it** (notification → incident response form). User-confirmed = treat as compromise. No report after 24h with multiple pushes = also suspicious (user may not realize).
3. **Do NOT assume OAuth consent abuse.** T1621 is about Authenticator push spam — not app registration consent. (Common LLM confusion: `suspiciousAuthAppApproval` despite the name is MFA-related, NOT app consent.)
4. **Look for prior `unfamiliarFeatures` or `anonymizedIPAddress` risk events** on the same user — MFA fatigue rarely arrives alone in a real attack.

---

## When investigating an alert that fires on PowerShell, ALWAYS:

1. **Check `InitiatingProcessFileName` and `InitiatingProcessParentFileName`** before assuming malicious intent. Common parents that explain away alerts:
   - `senseir.exe` → MDE Live Response / Automated Investigation (Microsoft signed)
   - `<EDR vendor process>` → product agent
   - `wsmprovhost.exe` → WinRM remote management (legit admin)
   - `mssense.exe` → MDE itself
2. **Check signing status:** `InitiatingProcessSignerType == "ValidSignature"` filters out the bulk of legitimate enterprise tooling.
3. **Check the script content path:** PowerShell from `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\` is MDE. From `C:\Users\<user>\AppData\Local\Temp\` is much higher signal.
4. **Encoded commands ≠ malicious by default.** Many enterprise scripts use `-EncodedCommand` to avoid quoting hell. Decode and read the actual command before escalating.

---

## When closing an investigation, ALWAYS:

1. **Cite the specific evidence** that led to the verdict. "Looks benign" is not closure — "AbuseIPDB score 0, IP is in `<corp range>`, user is in `<validated personnel>` list, no anomalies in 30-day baseline" is closure.
2. **If the verdict is FP, write down WHY** — add a one-line entry to the tenant-context Lessons Learned. The next analyst will save the time you just spent.
3. **If the verdict is TP, document the IOCs** — the IPs, hashes, UPNs, app IDs that confirmed compromise. Future hunts depend on this.
4. **If the verdict is "indeterminate"**, say so explicitly. Do not invent a verdict to look decisive. Capture what data was missing (which table wasn't accessible, which entity couldn't be enriched).

---

## Anti-patterns Copilot should refuse:

- **"Probably benign"** without a stated reason → demand evidence
- **"Typical attacker behavior"** when no baseline was queried → demand the baseline query
- **"Should be investigated further"** without naming what to investigate → demand specifics
- **Recommending state-changing PowerShell** (Remove-*, Set-*, Disable-*) → use portal links instead
- **Claiming a query "found nothing"** without showing the query → demand the executed KQL

---

## Memory hygiene reminders:

- **User memory** (`/memories/`) — your personal preferences, KQL shortcuts, ergonomic notes. Stays with you across all workspaces.
- **Repo memory** (`/memories/repo/`) — tenant-specific facts, FP patterns, validated personnel. Shared via the sync script.
- **Session memory** (`/memories/session/`) — current investigation only. Gets cleared.

If you find yourself re-typing the same context into chat across sessions, it belongs in repo memory.
