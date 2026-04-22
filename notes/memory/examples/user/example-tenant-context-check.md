# Example: User-memory trigger rule for tenant context

> **What this is.** A template for a small file you place in **user memory**
> (`/memories/`) — NOT repo memory. User memory is the only tier Copilot
> auto-loads at chat start (first ~200 lines), so this is what reliably
> triggers Copilot to pull in your repo-memory facts when investigating
> your tenant.
>
> **Why it exists.** Repo memory (`/memories/repo/`) is rich (tenant IDs,
> infrastructure IPs, validated personnel, known FP patterns), but Copilot
> only sees *filenames* from that scope at chat start — not contents. Without
> a trigger rule, Copilot may write a confident "🔴 CRITICAL — investigate
> immediately" assessment on activity that's actually documented in repo
> memory as a known false-positive (vendor agent, scheduled task, lab
> automation, etc.).
>
> **Design principle: keep the trigger lean.** The trigger's only job is to
> (a) detect tenant signals and (b) make Copilot open the repo file. Do NOT
> duplicate facts (IPs, account lists, FP patterns) inside the trigger —
> they belong in the repo file, which is the single source of truth.
> User memory has a shared ~200-line auto-load budget; every line in this
> file crowds out room for other triggers and other workspaces.
>
> **How to use:**
> 1. Copy the template below (between the `---` markers) into your user
>    memory as `/memories/<your-tenant>-context-check.md`
> 2. Replace every `<placeholder>` in the trigger clause with real values
> 3. Make sure the `repo/<your-tenant>.md` file actually exists (use
>    `examples/repo/example-tenant-context.md` as a starting point)
> 4. Add ALL the specific facts (IPs, personnel, FP rules, lessons learned)
>    to the **repo file**, NOT to this trigger

---

# <Tenant Name> — Mandatory Context Check Before Drill-Downs

**Trigger:** Any time `tenant_id` is `<your-tenant-guid>` (and any
secondary tenant IDs you've observed), OR Sentinel workspace ID is
`<your-workspace-guid>`, OR a UPN ends in `@<yourcompany.com>` (and any
other domains: `@<acquired-co.com>`, `@<lab-tenant.com>`).

> Trigger signals are intentionally limited to **stable identifiers only**
> — tenant IDs, workspace IDs, domain suffixes. Do NOT add IPs, account
> names, personnel UPNs, or CIDR ranges here; those go in the repo file.

**Required action BEFORE writing any risk assessment, recommendation,
"compromised" verdict, or escalation:**

1. Read `/memories/repo/<your-tenant>.md` in full
2. Apply the documented checks (known infrastructure IPs, validated
   personnel, false-positive patterns, automation windows, etc.) before
   classifying any finding

If signals match a documented pattern → classify as known/expected, do
not escalate. If signals do NOT match → proceed with normal investigation,
but explicitly cite that you checked.

---

## Variations / additional triggers you may want to add

If you have multiple tenants, create one trigger file per tenant. They
all auto-load into every chat, but each only fires its read-step when its
specific tenant signals appear.

For very high-noise environments, you can add narrower trigger files
following the same lean pattern:

- `/memories/honeypot-accounts-context-check.md` — trigger on specific UPNs,
  read `repo/honeypot-accounts.md`
- `/memories/infra-context-check.md` — trigger on specific CIDR ranges,
  read `repo/infrastructure.md`
- `/memories/rmm-tools-context-check.md` — trigger on RMM-related queries,
  read `repo/known-rmm-fp-patterns.md`

Each trigger should stay around 10–15 lines. The detail lives in the repo
file it points at.
