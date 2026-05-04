# Code of Conduct AiTM Phishing Campaign — TTPs & IOCs

**Created:** 2026-05-04  
**Platform:** Both  
**Tables:** EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents, DeviceFileEvents, AADUserRiskEvents  
**Keywords:** code of conduct, COC, conduct policy, conduct review, non-compliance case, case log, disciplinary action, awareness case log, Internal Regulatory COC, Workforce Communications, Team Conduct Report, Paubox, HIPAA encrypted, cocinternal, gadellinet, harteprn, businesshellosign, compliance-protectionoutlook, acceptable-use-policy-calendly, .de TLD phish, multi-stage CAPTCHA, Cloudflare CAPTCHA, intermediate staging page, AiTM, adversary-in-the-middle, anomalous token, OfficeHome, PDF lure  
**MITRE:** T1566.001, T1566.002, T1204.001, T1204.002, T1539, T1078, T1556.006, TA0001, TA0006  
**Domains:** email, identity  
**Timeframe:** Last 30 days (configurable)

---

## Threat Overview

[Microsoft Threat Intelligence — Breaking the code: Multi-stage 'code of conduct' phishing campaign leads to AiTM token compromise (May 4, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/) reports a large-scale AiTM credential theft campaign observed **April 14–16, 2026** that targeted **35,000+ users across 13,000+ organizations in 26 countries** (92% United States). Top sectors: Healthcare & life sciences (19%), Financial services (18%), Professional services (11%), Technology & software (11%).

**Distinguishing TTPs (vs prior AiTM campaigns):**

| TTP | Detail | Defender impact |
|---|---|---|
| **"Code of Conduct" lure theme** | Display names like *Internal Regulatory COC*, *Workforce Communications*, *Team Conduct Report*; subjects like *"Internal case log issued under conduct policy"*, *"Reminder: employer opened a non-compliance case log"* | Novel social engineering theme creating urgency around employee discipline |
| **Polished enterprise-style HTML** | Body includes preemptive authenticity statement ("issued through an authorized internal channel") and a **Paubox green banner** simulating HIPAA-compliant encryption | Higher plausibility than typical phishing; defeats user pattern recognition |
| **PDF attachment delivery** | Filenames follow `Awareness Case Log File – <Weekday> <Day><ordinal>, <Month> <Year>.pdf` pattern (e.g., `Awareness Case Log File – Tuesday 14th, April 2026.pdf`); also `Disciplinary Action – Employee Device Handling Case.pdf` | PDFs contain "Review Case Materials" link that initiates the chain |
| **Attacker-controlled `.de` domains** | `compliance-protectionoutlook[.]de`, `acceptable-use-policy-calendly[.]de`, `na.businesshellosign[.]de` — `.de` TLD with compliance/policy/calendly/hellosign keyword stuffing | New TLD set not covered in Q1 2026 Tycoon2FA pivot (`.ru`/`.digital`/`.business`) |
| **Multi-stage CAPTCHA gating** | Stage 1: Cloudflare CAPTCHA on attacker domain → Stage 2: intermediate "encrypted documentation" page → Stage 3: image-selection CAPTCHA → Stage 4: platform-aware (mobile vs desktop) redirect → Stage 5: AiTM Microsoft sign-in page | Designed to defeat sandbox detonation and automated URL analysis |
| **Legitimate email delivery service abuse** | Messages sent from cloud-hosted Windows VM via legitimate ESP, fully authenticated (DMARC/DKIM/SPF passing) | Cannot rely on email auth failures alone for detection |
| **Sender domains hosting addresses** | `cocinternal[.]com`, `gadellinet[.]com`, `harteprn[.]com` (also reused as link host `na.businesshellosign[.]de`) | Likely attacker-registered and rotating |

**Coverage delta vs existing query files:**

- [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md) — covers general phishing, AiTM full chain, ZAP failure, Safe Links clicks. Does **not** cover code-of-conduct lures, PDF-specific AiTM chains, or `.de` compliance-themed domain hunting.
- [`queries/identity/aitm_threat_detection.md`](../../identity/aitm_threat_detection.md) — covers post-auth AiTM detection (OfficeHome, anomalous tokens). Does **not** correlate back to PDF-delivered phish or this campaign's specific lure theme.
- [`queries/threat-intelligence/2026-04/email_threat_landscape_q1_2026.md`](../2026-04/email_threat_landscape_q1_2026.md) — covers Q1 2026 Tycoon2FA TLD pivot (`.ru`/`.digital`/`.business`), SVG CAPTCHA campaign, body-embedded QR proxy. Does **not** cover `.de` TLD or code-of-conduct PDF lures.
- **This file (NEW):** Hard IOC sweep, code-of-conduct lure detection, weekday-prefixed PDF filename pattern, campaign hash sweep across email + endpoint, `.de` compliance-themed URL hunting, end-to-end PDF→AiTM compromise chain.

---

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Campaign IOC Sweep — Domains, Senders, Hashes](#query-1-campaign-ioc-sweep--domains-senders-hashes) | Investigation | `EmailEvents` |
| 2 | [Code of Conduct Lure — Display Name & Subject Pattern](#query-2-code-of-conduct-lure--display-name--subject-pattern) | Investigation | `EmailEvents` |
| 3 | [PDF Attachment with Weekday-Prefixed Filename](#query-3-pdf-attachment-with-weekday-prefixed-filename) | Investigation | `EmailAttachmentInfo` + `EmailEvents` |
| 4 | [Campaign PDF Hash Sweep — Email and Endpoint](#query-4-campaign-pdf-hash-sweep--email-and-endpoint) | Investigation | `DeviceFileEvents` + multi |
| 5 | [Suspicious `.de` TLD URLs in Inbound Phish — Compliance/Policy Theme](#query-5-suspicious-de-tld-urls-in-inbound-phish--compliancepolicy-theme) | Posture | `EmailEvents` + `EmailUrlInfo` |
| 6 | [PDF Phish → URL Click → Anomalous Token (60-min AiTM Chain)](#query-6-pdf-phish--url-click--anomalous-token-60-min-aitm-chain) | Detection | `AADUserRiskEvents` + multi |


## IOC Reference

| Type | Value | Context |
|------|-------|---------|
| **Domain** | `compliance-protectionoutlook[.]de` | Stage 1 landing page (April 14–16, 2026) |
| **Domain** | `acceptable-use-policy-calendly[.]de` | Stage 1 landing page (April 14–16, 2026) |
| **Domain** | `cocinternal[.]com` | Sender email host |
| **Domain** | `gadellinet[.]com` | Sender email host |
| **Domain** | `harteprn[.]com` | Sender email host |
| **Domain** | `na.businesshellosign[.]de` | Sender email host |
| **Sender** | `cocpostmaster@cocinternal.com` | Campaign sender |
| **Sender** | `nationaladmin@gadellinet.com` | Campaign sender |
| **Sender** | `nationalintegrity@harteprn.com` | Campaign sender |
| **Sender** | `m365premiumcommunications@cocinternal.com` | Campaign sender |
| **Sender** | `documentviewer@na.businesshellosign.de` | Campaign sender |
| **Filename** | `Awareness Case Log File – <Weekday> <Day><ordinal>, <Month> <Year>.pdf` | Daily-rotated PDF lure (e.g., `… – Monday 13th, April 2026.pdf`) |
| **Filename** | `Disciplinary Action – Employee Device Handling Case.pdf` | Alternate PDF lure |
| **SHA-256** | `5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6` | Campaign PDF hash |
| **SHA-256** | `B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD` | Campaign PDF hash |
| **SHA-256** | `11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D` | Campaign PDF hash |
| **Display name** | `Internal Regulatory COC`, `Workforce Communications`, `Team Conduct Report` | Sender display strings |
| **Subject themes** | "Internal case log issued under conduct policy", "Reminder: employer opened a non-compliance case log" | Q2 2026 lure templates |

---

## Query 1: Campaign IOC Sweep — Domains, Senders, Hashes

Multi-table union sweep for the **published campaign IOCs**: 6 attacker-controlled domains, 5 sender email addresses, and 3 PDF SHA-256 hashes. Searches `EmailEvents` (delivered/blocked messages), `EmailUrlInfo` (URLs in body/attachment scans), `EmailAttachmentInfo` (file hashes), and `UrlClickEvents` (Safe Links activations). Use this as the first triage query when responding to the article.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Code-of-conduct AiTM campaign IOC match — {{Source}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Quarantine related messages via Threat Explorer. If UrlClickEvents matches, treat the user as suspected AiTM compromise: revoke refresh tokens, force password reset, hunt for inbox forwarding rules, and check for OfficeHome anomalous token within 60 min of click."
adaptation_notes: "AH-native. Uses Timestamp on all four tables (XDR-native). EmailEvents filters cover both SenderMailFromAddress (envelope) and SenderFromAddress (header) since both can be IOC-relevant. IOC list is point-in-time (April 14-16 wave) - refresh as new infrastructure is identified."
-->
```kql
// Code-of-conduct AiTM campaign: hard IOC sweep (domains + senders + hashes)
let lookback = 30d;
let iocDomains = dynamic([
  "compliance-protectionoutlook.de","acceptable-use-policy-calendly.de",
  "cocinternal.com","gadellinet.com","harteprn.com",
  "na.businesshellosign.de","businesshellosign.de"
]);
let iocSenders = dynamic([
  "cocpostmaster@cocinternal.com","nationaladmin@gadellinet.com",
  "nationalintegrity@harteprn.com","m365premiumcommunications@cocinternal.com",
  "documentviewer@na.businesshellosign.de"
]);
let iocHashes = dynamic([
  "5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6",
  "B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD",
  "11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D"
]);
union
  ( EmailEvents
    | where Timestamp > ago(lookback)
    | where SenderMailFromAddress in~ (iocSenders) or SenderFromAddress in~ (iocSenders)
        or SenderMailFromDomain in~ (iocDomains) or SenderFromDomain in~ (iocDomains)
    | extend Source = "EmailEvents"
    | project Timestamp, Source, NetworkMessageId, SenderFromAddress, SenderIPv4,
              RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes ),
  ( EmailUrlInfo
    | where Timestamp > ago(lookback)
    | where UrlDomain has_any (iocDomains)
    | extend Source = "EmailUrlInfo"
    | project Timestamp, Source, NetworkMessageId, Url, UrlDomain ),
  ( EmailAttachmentInfo
    | where Timestamp > ago(lookback)
    | where SHA256 in~ (iocHashes)
    | extend Source = "EmailAttachmentInfo"
    | project Timestamp, Source, NetworkMessageId, FileName, FileSize, SHA256, ThreatTypes ),
  ( UrlClickEvents
    | where Timestamp > ago(lookback)
    | where Url has_any (iocDomains)
    | extend Source = "UrlClickEvents"
    | project Timestamp, Source, AccountUpn, Url, IPAddress, ActionType, NetworkMessageId )
| order by Timestamp desc
```

**Tuning:**
- IOC list is **point-in-time** (April 14–16, 2026 wave). The campaign infrastructure was likely sinkholed/blocked shortly after publication; expect new domains/senders for follow-on waves.
- `UrlClickEvents` matches are **highest priority** — the user has reached the Cloudflare CAPTCHA stage and may have proceeded to the AiTM proxy. Pair with Query 6 to confirm token compromise.
- `EmailAttachmentInfo` SHA-256 matches confirm **delivery** of the campaign PDF even if the message was later quarantined by ZAP.

---

## Query 2: Code of Conduct Lure — Display Name & Subject Pattern

Pattern-based hunt for the **code-of-conduct lure theme** beyond the published IOCs. Detects the campaign's distinctive language across `SenderDisplayName` (e.g., *Internal Regulatory COC*, *Workforce Communications*) and `Subject` (e.g., *"non-compliance case log"*, *"conduct policy"*). Useful for catching follow-on waves where infrastructure has rotated but the social-engineering template persists.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "InitialAccess"
title: "Inbound 'code of conduct' phishing lure pattern detected"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Render the message in Threat Explorer to validate the lure. Look for the Paubox green banner and a 'Review Case Materials' PDF attachment. Quarantine campaign messages via Threat Explorer and add the SenderFromDomain to Tenant Allow/Block List."
adaptation_notes: "AH-native. Uses Timestamp. Two-axis filter (display name OR subject) provides reasonable precision; combine with ThreatTypes = Phish or DeliveryAction != Blocked for higher confidence in noisy environments. Display-name match on its own is high-confidence; subject-only match warrants triage."
-->
```kql
// Code-of-conduct AiTM campaign: lure-theme pattern hunt (display name + subject)
let lookback = 30d;
let cocDisplayNameKeywords = dynamic([
  "internal regulatory coc","workforce communications","team conduct report",
  "internal regulatory","conduct report","regulatory coc"
]);
let cocSubjectKeywords = dynamic([
  "code of conduct","conduct policy","conduct review","non-compliance case",
  "case log issued","awareness case log","disciplinary action","employer opened",
  "non compliance case"
]);
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection in ("Inbound","Intra-org")
| extend SubjectLower = tolower(Subject), DisplayLower = tolower(SenderDisplayName)
| extend DisplayMatch = DisplayLower has_any (cocDisplayNameKeywords)
| extend SubjectMatch = SubjectLower has_any (cocSubjectKeywords)
| where DisplayMatch or SubjectMatch
| extend Confidence = case(DisplayMatch and SubjectMatch, "High",
                            DisplayMatch, "Medium-High",
                            "Medium")
| project Timestamp, Confidence, SenderFromAddress, SenderDisplayName, SenderIPv4,
          RecipientEmailAddress, Subject, AttachmentCount, UrlCount, DeliveryAction,
          ThreatTypes, DetectionMethods, NetworkMessageId
| order by Timestamp desc
```

**Tuning:**
- `Confidence == "High"` (display + subject both match) is rarely a false positive — internal HR/compliance teams generally do not use these exact phrasings in inbound external mail.
- For environments with active employee-relations communications from external HR vendors, allow-list trusted senders: `| where SenderFromDomain !endswith "@<your-trusted-hr-vendor>.com"`.
- To raise precision, add `| where ThreatTypes has "Phish" or DeliveryAction != "Delivered"` — but be aware the campaign uses fully-authenticated mail and may evade reputation-based filtering.

---

## Query 3: PDF Attachment with Weekday-Prefixed Filename

Detects the **distinctive PDF filename pattern** used by the campaign: `Awareness Case Log File – <Weekday> <Day><ordinal>, <Month> <Year>.pdf` (e.g., `Awareness Case Log File – Tuesday 14th, April 2026.pdf`). The pattern combines a compliance/disciplinary keyword, a weekday name, and an ordinal day-of-month — a structurally-distinct fingerprint rarely used in legitimate business attachments.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "InitialAccess"
title: "Inbound PDF with code-of-conduct campaign filename pattern: {{FileName}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Compute the SHA-256 of the attachment and compare against published campaign hashes (Query 4). If matched, treat as confirmed campaign delivery. Quarantine and ZAP via Threat Explorer."
adaptation_notes: "AH-native. Uses Timestamp. Regex enforces both keyword AND weekday/ordinal markers - high precision. Inbound + Intra-org scope (campaign was Inbound but spoofed senders may appear Intra-org)."
-->
```kql
// Code-of-conduct AiTM campaign: weekday-prefixed PDF filename pattern
let lookback = 30d;
let keywordRegex = @"(?i)(awareness|disciplinary|conduct|case log|compliance review|review case)";
let weekdayRegex = @"(?i)(monday|tuesday|wednesday|thursday|friday|saturday|sunday)";
let ordinalRegex = @"\d{1,2}(st|nd|rd|th)";
EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where FileType in~ ("pdf")
| where FileName matches regex keywordRegex
| where FileName matches regex weekdayRegex or FileName matches regex ordinalRegex
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection in ("Inbound","Intra-org")
  ) on NetworkMessageId
| project Timestamp, FileName, FileSize, SHA256, SenderFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes, NetworkMessageId
| order by Timestamp desc
```

**Tuning:**
- Filename match alone is **high-confidence** — the keyword + weekday + ordinal triple is a campaign signature, not a generic naming convention.
- For follow-on waves with the alternate `Disciplinary Action – Employee Device Handling Case.pdf` shape, add: `or FileName matches regex @"(?i)employee device handling"`.
- Capture the SHA-256 from matches and feed back into Query 4 to extend the campaign hash set.

---

## Query 4: Campaign PDF Hash Sweep — Email and Endpoint

Two-stage hash sweep: (a) `EmailAttachmentInfo` confirms the malicious PDF was **delivered** to a mailbox, (b) `DeviceFileEvents` confirms the user **opened/saved** the PDF on an MDE-onboarded endpoint. The Defender XDR portal renders both in the same incident, but this query gives a direct correlation table for incident response.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Code-of-conduct AiTM campaign PDF SHA-256 observed — {{Source}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
  - type: "device"
    identifier: "deviceName"
recommendedActions: "If endpoint match: hunt the recipient user's sign-in events for OfficeHome AiTM markers in the next 60 min. Quarantine the file via Defender XDR. ZAP related email via Threat Explorer."
adaptation_notes: "AH-native. Uses Timestamp on both tables. Hash list will need refresh as new PDF variants emerge - capture new SHA-256s from Query 3 matches and append."
-->
```kql
// Code-of-conduct AiTM campaign: PDF hash sweep across email and endpoint
let lookback = 30d;
let iocHashes = dynamic([
  "5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6",
  "B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD",
  "11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D"
]);
union
  ( EmailAttachmentInfo
    | where Timestamp > ago(lookback)
    | where SHA256 in~ (iocHashes)
    | join kind=leftouter (
        EmailEvents | where Timestamp > ago(lookback)
        | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, DeliveryAction, Subject
      ) on NetworkMessageId
    | extend Source = "EmailAttachmentInfo"
    | project Timestamp, Source, FileName, SHA256, SenderFromAddress, RecipientEmailAddress,
              Subject, DeliveryAction ),
  ( DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where SHA256 in~ (iocHashes)
    | extend Source = "DeviceFileEvents"
    | project Timestamp, Source, DeviceName, ActionType, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessAccountUpn )
| order by Timestamp desc
```

**Tuning:**
- A `DeviceFileEvents` match where `ActionType` is `FileCreated` and `FolderPath` resolves to a browser-download or mail-attachment cache directory means the user **saved or opened the PDF locally** — escalate to user-investigation immediately.
- For environments without MDE coverage on all endpoints, the email arm of the union still provides delivery confirmation.

---

## Query 5: Suspicious `.de` TLD URLs in Inbound Phish — Compliance/Policy Theme

The published IOCs use **`.de` TLD attacker-controlled domains with compliance/policy/calendly/hellosign keyword stuffing** (e.g., `compliance-protectionoutlook[.]de`, `acceptable-use-policy-calendly[.]de`). This is a **new TLD pattern** not covered by the Q1 2026 Tycoon2FA pivot (which focused on `.ru`/`.digital`/`.business`). This query hunts for inbound phish URLs on `.de` domains with at least one campaign-style keyword in the hostname.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "InitialAccess"
title: "Inbound phish URL on .de domain with compliance keyword: {{host}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Validate the URL category in MDTI. If unknown/malicious, add to Tenant Allow/Block List. Cross-reference recipients with UrlClickEvents (Query 6) to identify users who proceeded to the AiTM proxy."
adaptation_notes: "AH-native. UrlDomain is string - last token after '.' is the TLD. Score-based gating (>=1 keyword marker) reduces FP from legitimate German-business inbound URLs. Inbound + Phish required."
-->
```kql
// Code-of-conduct AiTM campaign: .de TLD inbound phish with compliance/policy keywords
let lookback = 30d;
EmailUrlInfo
| where Timestamp > ago(lookback)
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Inbound"
    | where ThreatTypes has "Phish"
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderIPv4,
              Subject, ThreatTypes, DeliveryAction
  ) on NetworkMessageId
| extend tld = tolower(tostring(split(UrlDomain, ".")[-1]))
| where tld == "de"
| extend host = tolower(UrlDomain)
| extend SuspiciousMarkers = pack_array(
    iff(host has "compliance",1,0),
    iff(host has "policy",1,0),
    iff(host has "outlook",1,0),
    iff(host has "calendly",1,0),
    iff(host has "hellosign",1,0),
    iff(host has "docusign",1,0),
    iff(host has "review",1,0),
    iff(host has "case",1,0),
    iff(host has "secure",1,0),
    iff(host has "conduct",1,0),
    iff(host has "regulatory",1,0))
| extend MarkerScore = toint(array_sum(SuspiciousMarkers))
| where MarkerScore >= 1
| summarize Count=count(), Recipients=dcount(RecipientEmailAddress), Senders=dcount(SenderFromAddress),
            SampleHosts=make_set(host, 25), SampleSenders=make_set(SenderFromAddress, 10),
            MaxScore=max(MarkerScore), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
            by SenderFromDomain
| order by Count desc
```

**Tuning:**
- `MaxScore >= 2` is a higher-confidence subset — multi-keyword stuffing in a `.de` hostname is rare in legitimate German business infrastructure.
- Allow-list known German partners and SaaS providers if needed: `| where not(host has_any ("<your-trusted-de-domain1>","<your-trusted-de-domain2>"))`.
- For organisations operating in DACH region with significant legitimate `.de` mail flow, raise the gate to `MarkerScore >= 2` and pair with `DeliveryAction != "Blocked"` to focus on what reached users.

---

## Query 6: PDF Phish → URL Click → Anomalous Token (60-min AiTM Chain)

End-to-end **AiTM compromise chain** specific to this campaign's PDF-delivered model. Joins three signals within a 60-minute window:

1. **Inbound PDF phish** delivered to a mailbox (`EmailEvents` + `EmailAttachmentInfo`)
2. **Safe Links click-through** by the same recipient on a URL extracted from that message (`UrlClickEvents` with `ActionType in ("ClickAllowed","UrlClickThrough")`)
3. **Anomalous token / unfamiliar features** Identity Protection event for the same user (`AADUserRiskEvents`)

This is the highest-confidence post-compromise indicator for this campaign — generic AiTM detections (existing `email_threat_detection.md` Query 3.2) catch the broader pattern, but this query specifically anchors on the PDF lure delivery rather than HTML/URL-only phish.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-table join with 60-min temporal correlation across three tables - too complex for current CD rule limits. Use as scheduled hunt or convert to Sentinel analytic rule. The chain semantics (PDF -> click -> token) are the high-confidence signal; collapsing to two tables loses precision. AH-eligible for ad-hoc but not CD."
-->
```kql
// Code-of-conduct AiTM campaign: end-to-end PDF -> click -> anomalous token chain
let lookback = 30d;
let chainWindow = 60min;
let pdfPhish = EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Inbound"
    | where ThreatTypes has "Phish" or AttachmentCount > 0
    | join kind=inner (
        EmailAttachmentInfo
        | where Timestamp > ago(lookback)
        | where FileType =~ "pdf"
        | project NetworkMessageId, FileName, SHA256
      ) on NetworkMessageId
    | project EmailTime=Timestamp, NetworkMessageId, RecipientEmailAddress,
              SenderFromAddress, Subject, FileName, SHA256;
let clicks = UrlClickEvents
    | where Timestamp > ago(lookback)
    | where ActionType in~ ("ClickAllowed","UrlClickThrough")
    | project ClickTime=Timestamp, AccountUpn, Url, IPAddress, NetworkMessageId;
let riskEvents = AADUserRiskEvents
    | where TimeGenerated > ago(lookback)
    | where RiskEventType in~ ("anomalousToken","unfamiliarFeatures","tokenIssuerAnomaly",
                                "suspiciousBrowser","suspiciousAPITraffic")
    | project RiskTime=TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, IpAddress,
              RiskDetail, Source;
pdfPhish
| join kind=inner (clicks) on NetworkMessageId
| where ClickTime between (EmailTime .. EmailTime + chainWindow)
| where RecipientEmailAddress =~ AccountUpn
| join kind=inner (riskEvents) on $left.AccountUpn == $right.UserPrincipalName
| where RiskTime between (ClickTime .. ClickTime + chainWindow)
| project EmailTime, ClickTime, RiskTime, AccountUpn, SenderFromAddress, Subject,
          FileName, SHA256, ClickedUrl=Url, ClickIp=IPAddress,
          RiskEventType, RiskLevel, RiskIp=IpAddress, RiskDetail
| order by EmailTime desc
```

**Tuning:**
- Match here is **near-confirmation** of AiTM token theft. Treat as P1: revoke refresh tokens, disable the user, force password + MFA re-registration, and hunt for inbox forwarding rules and OAuth grants in the 24 h window after `RiskTime`.
- `chainWindow = 60min` works for the typical click-to-auth interval; raise to `120min` if the campaign uses delayed multi-stage CAPTCHA flows that slow the user.
- `RiskEventType` list covers the documented Defender detections from the article (Anomalous Token, Unfamiliar sign-in properties for session cookies); add provider-specific event types (e.g., `mcasImpossibleTravel`) if you see them in your tenant.
- The `RecipientEmailAddress =~ AccountUpn` join assumes UPN equals primary SMTP — if your tenant uses split UPN/SMTP, adjust to use `RecipientObjectId` + Graph user lookup instead.

---

## References

- Microsoft Threat Intelligence — [Breaking the code: Multi-stage 'code of conduct' phishing campaign leads to AiTM token compromise (May 4, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/)
- Microsoft Threat Intelligence — [Email threat landscape: Q1 2026 trends and insights (April 30, 2026)](https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/)
- Microsoft Defender Threat Analytics — Threat overview profile: *Adversary-in-the-middle credential phishing*, *Evolving phishing threats*
- Companion files: [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md), [`queries/identity/aitm_threat_detection.md`](../../identity/aitm_threat_detection.md), [`queries/threat-intelligence/2026-04/email_threat_landscape_q1_2026.md`](../2026-04/email_threat_landscape_q1_2026.md)
