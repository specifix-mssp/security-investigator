# Trusted Third-Party Intrusion (HPE OA / HPOM Abuse) — TTPs & Hunting

**Created:** 2026-05-12  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceRegistryEvents, DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceImageLoadEvents  
**Keywords:** trusted relationship, third-party IT, HPE Operations Agent, HPE Operations Manager, HPOM, HP OpenView, opcacta, opcle, opcmona, opcmsga, network provider DLL, NPLogonNotify, NPPasswordChangeNotify, mslogon, password filter DLL, LSA notification package, passms, msupdate, credential interception, web shell, Errors.aspx, Signoff.aspx, ghost.inc, ngrok, RDP tunneling, WMI lateral movement, abc003.vbs, external IP discovery, Ipd file, icon02.jpeg  
**MITRE:** T1199, T1078, T1556.002, T1556.008, T1505.003, T1059.001, T1059.005, T1547.005, T1572, T1021.001, T1047, T1016, T1018, T1083  
**Domains:** endpoint, identity  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Microsoft Incident Response — Undermining the trust boundary: Investigating a stealthy intrusion through third-party compromise (May 12, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/)

---

## Threat Overview

Microsoft Incident Response (DART) reports a **123-day stealthy intrusion** in which a threat actor compromised a **third-party IT services provider** managing the victim's HPE Operations Manager (HPOM) / HPE Operations Agent (HPE OA) platform, then used that trusted operational channel to execute scripts, drop tooling, and steal credentials without triggering classic exploit-driven detections. This aligns with **MITRE ATT&CK T1199 — Trusted Relationship**.

### Attack Chain Summary

```
Compromised 3P IT provider → HPOM operator console → HPE OA on managed hosts
    → VBScript discovery (abc003.vbs) + web shell drop (Errors.aspx / Signoff.aspx / ghost.inc)
    → Malicious Network Provider DLL on DC01 (mslogon.dll → NPLogonNotify/NPPasswordChangeNotify)
        → cleartext creds to C:\Users\Public\Music\abc123c.d
    → Malicious Password Filter on DC01/DC02 (passms.dll registered as LSA Notification Package)
        → encoded creds to C:\ProgramData\WindowsUpdateService\UpdateDir\Ipd
    → msupdate.dll exfil (SMB → icon02.jpeg / SMTP "Update Service")
    → ngrok tunnels on internal servers → inbound RDP from threat actor
    → WMI used to push ngrok to additional hosts
```

### Distinguishing TTPs

| TTP | Detail | Why it evades detection |
|---|---|---|
| **HPE OA as delivery channel** | `opcacta.exe` / `opcle.exe` (HPE OA action / launcher agents) executed `abc003.vbs`, dropped DLLs, modified `Signoff.aspx` | Signed, allow-listed enterprise tooling; activity blends with legitimate operator-initiated automation |
| **Trusted-third-party origin** | Operator console (HPOM) and the credentials driving it were owned by an outsourced IT provider | No internal user attribution; perimeter trust boundary effectively bypassed |
| **Network Provider DLL hijack** | `mslogon` registered under `HKLM\System\CurrentControlSet\Services\<name>\NetworkProvider` and added to `\Control\NetworkProvider\Order` — DLL exports `NPLogonNotify` / `NPPasswordChangeNotify` to capture cleartext creds at sign-in & password change | Uses documented Windows extensibility; no LSASS injection or token theft signal |
| **LSA Notification Package** | `passms.dll` added to `HKLM\System\CurrentControlSet\Control\Lsa\Notification Packages` on domain controllers; `PasswordFilter()` API receives cleartext on every password set/change | Loaded by LSASS as a "legitimate" filter — typical LSASS-protection controls do not block it |
| **Encoded credential staging** | Captured passwords double-encoded (Base64 + custom alphabet) and written to `C:\ProgramData\WindowsUpdateService\UpdateDir\Ipd`; companion `msupdate.dll` ships them via SMB as `icon02.jpeg` or SMTP with subject *"Update Service"* | Cleartext signatures and DLP keyword rules miss the encoded payload; `.jpeg` masquerade defeats simple file-type egress filters |
| **Web shell persistence on web tier** | Initial `Errors.aspx` web shell drops files; later `Signoff.aspx` is **modified** (not replaced) to load `ghost.inc` from `%TEMP%` | File-creation-only detections miss `Signoff.aspx` modification; servers in scope had no EDR coverage |
| **ngrok-fronted RDP** | `ngrok` deployed on SQL-01 and other internal servers with outbound internet; inbound RDP arrives over the tunnel | Defeats perimeter ACL / RDP brute-force telemetry — the inbound source IP is loopback / tunnel egress |
| **WMI distribution of ngrok** | Compromised web servers used `wmiprvse.exe` to spawn ngrok on additional internal hosts | Lateral movement without SMB/PsExec signals |

### Coverage Delta vs Existing Query Library

| Existing file | Overlap | Gap this file fills |
|---|---|---|
| `queries/endpoint/startup_folder_persistence.md` | None | Authentication-package persistence (NetworkProvider, LSA Notification) is distinct from autostart persistence |
| `queries/endpoint/rare_process_chains.md` | Generic parent-child rarity | No specific HPE OA / `opc*.exe` parent chain |
| `queries/endpoint/smb_threat_detection.md` | SMB-based lateral movement | Does not cover `.jpeg`-masqueraded SMB writes to staging shares |
| `queries/endpoint/rdp_threat_detection.md` | RDP brute force / lateral RDP | Does not cover RDP arriving over ngrok loopback tunnel |
| `queries/identity/aitm_threat_detection.md` | Cloud token theft | Does not cover on-prem cleartext credential capture via network provider / password filter |

**This file (NEW):** End-to-end on-prem hunting for trusted-third-party IT tooling abuse, authentication-package backdoors, and ngrok-fronted persistence — modeled directly on the May 12 2026 DART case study.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Suspicious LSA Notification Package (Password Filter) Registered](#query-1-suspicious-lsa-notification-package-password-filter-registered) | Investigation | `DeviceFileEvents` + `DeviceRegistryEvents` |
| 2 | [Suspicious Network Provider DLL Registered](#query-2-suspicious-network-provider-dll-registered) | Investigation | `DeviceFileEvents` + `DeviceRegistryEvents` |
| 3 | [Unsigned DLL Loaded by LSASS as Notification Package or Network Pro...](#query-3-unsigned-dll-loaded-by-lsass-as-notification-package-or-network-provider) | Investigation | `DeviceImageLoadEvents` |
| 4 | [HPE Operations Agent Spawning Script Interpreters](#query-4-hpe-operations-agent-spawning-script-interpreters) | Investigation | `DeviceProcessEvents` |
| 5 | [VBScript Discovery and External-IP Reconnaissance](#query-5-vbscript-discovery-and-external-ip-reconnaissance) | Investigation | `DeviceProcessEvents` |
| 6 | [Web Shell Creation or Modification on IIS](#query-6-web-shell-creation-or-modification-on-iis) | Investigation | `DeviceFileEvents` |
| 7 | [Credential Drop File Path Indicators](#query-7-credential-drop-file-path-indicators) | Investigation | `DeviceFileEvents` |
| 8 | [Filename IOC Sweep (mslogon / passms / msupdate / ghost.inc / abc003)](#query-8-filename-ioc-sweep-mslogon--passms--msupdate--ghostinc--abc003) | Investigation | `DeviceFileEvents` + multi |
| 9 | [ngrok Execution and Tunnel Network Activity](#query-9-ngrok-execution-and-tunnel-network-activity) | Investigation | `DeviceNetworkEvents` + `DeviceProcessEvents` |
| 10 | [WMI Remote Execution Spawning Tunnel Tools](#query-10-wmi-remote-execution-spawning-tunnel-tools) | Investigation | `DeviceProcessEvents` |
| 11 | [Image-Masquerade Files Created Over SMB](#query-11-image-masquerade-files-created-over-smb) | Investigation | `DeviceFileEvents` |
| 12 | [Correlated Defender Alerts for T1199 / Credential Interception](#query-12-correlated-defender-alerts-for-t1199--credential-interception) | Detection | `AlertInfo` |


## IOC Reference

> The DART blog publishes **filenames, paths, and registry artifacts** but does **not** publish hashes or external C2 IPs for the credential-theft DLLs. All indicators below are behavioral / path-based.

| Type | Value | Context |
|---|---|---|
| **Filename** | `mslogon.dll` | Malicious network provider DLL (cred capture at sign-in) |
| **Filename** | `passms.dll` | Malicious password filter DLL (cred capture at password change) |
| **Filename** | `msupdate.dll` | Exfil module (SMB → `icon02.jpeg` / SMTP "Update Service") |
| **Filename** | `abc003.vbs` | VBScript launched by HPE OA for discovery |
| **Filename** | `Errors.aspx` | Initial web shell (file write / upload capability) |
| **Filename** | `ghost.inc` | Secondary web shell loaded from `%TEMP%` by modified `Signoff.aspx` |
| **Filename** | `icon02.jpeg` | SMB exfil masquerade file |
| **Path** | `C:\Users\Public\Music\abc123c.d` | Cleartext credential drop (from `mslogon.dll`) |
| **Path** | `C:\ProgramData\WindowsUpdateService\UpdateDir\Ipd` | Encoded credential drop (from `passms.dll`) |
| **Path fragment** | `\ProgramData\WindowsUpdateService\` | Attacker staging directory |
| **Registry** | `HKLM\System\CurrentControlSet\Control\NetworkProvider\Order` — `ProviderOrder` value containing `mslogon` (or any non-default name) | Network provider DLL hijack |
| **Registry** | `HKLM\System\CurrentControlSet\Services\<name>\NetworkProvider` — `ProviderPath` REG_EXPAND_SZ pointing at unsigned DLL | Network provider DLL hijack |
| **Registry** | `HKLM\System\CurrentControlSet\Control\Lsa\Notification Packages` — value `passms` (or any non-default name) | Malicious LSA password filter |
| **Process** | `ngrok.exe` (and variants) | Tunneling tool for inbound RDP |
| **Process tree** | `opcacta.exe` / `opcle.exe` / `opcmona.exe` → `cscript.exe` / `wscript.exe` / `powershell.exe` / `cmd.exe` | HPE OA spawning script interpreters |
| **SMTP subject** | `Update Service` | Email exfil from `msupdate.dll` |
| **ATT&CK** | T1199, T1078, T1556.002, T1556.008, T1505.003, T1547.005, T1572 | Primary techniques |

---

---

## Query 1: Suspicious LSA Notification Package (Password Filter) Registered

Detects new entries in `HKLM\...\Lsa\Notification Packages`. Windows defaults are `scecli`, `rassfm`, `kdcsvc` (DCs only). Any other entry — `passms`, `mslogon`, etc. — is suspicious and must load as a DLL into LSASS, giving cleartext password visibility. Joins to `DeviceFileEvents` to retrieve the on-disk path and invokes `FileProfile()` to flag unsigned / invalid-signature DLLs.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
mitreTechniques: ["T1556.002"]
title: "Suspicious LSA Notification Package registered on {{DeviceName}}"
severity: "high"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Treat as confirmed credential interception until proven otherwise. Isolate the host (DC if applicable), capture the DLL listed under C:\\Windows\\System32\\<name>.dll, submit to threat analytics, reset the krbtgt and all privileged passwords twice, and review domain replication for the same package value."
adaptation_notes: "AH-native. Uses FileProfile() so retains AH-only deployment path. ingestion_time() preferred over Timestamp filter for CD; using Timestamp here so it doubles as an investigation query."
-->
```kql
// Suspicious LSA Notification Package (password filter) registration — adapted from DART blog (2026-05-12)
let lookback = 30d;
let defaults = dynamic(["scecli","rassfm","kdcsvc"]);
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where RegistryKey has @"\Control\Lsa"
| where RegistryValueName =~ "Notification Packages"
| where isnotempty(RegistryValueData)
| extend Packages = split(RegistryValueData, " ")
| mv-expand Package = Packages to typeof(string)
| extend Package = tolower(trim(@"\s", Package))
| where isnotempty(Package) and Package !in~ (defaults)
| extend DllPath = tolower(strcat(@"c:\windows\system32\", Package, ".dll"))
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | extend DllPath = tolower(FolderPath)
    | project DeviceName, SHA1, DllPath
) on DeviceName, DllPath
| invoke FileProfile(SHA1, 1000)
| where isempty(SHA1) or SignatureState in~ ("SignedInvalid","Unsigned")
| project Timestamp, DeviceName, Package, DllPath, SHA1, Signer, SignatureState, IsExecutable, GlobalPrevalence, RegistryValueData
| order by Timestamp desc
```

---

## Query 2: Suspicious Network Provider DLL Registered

Detects custom entries in `\Control\NetworkProvider\Order` and their corresponding `ProviderPath` registrations. Windows-built-in providers (`RDPNP`, `LanmanWorkstation`, `webclient`) are excluded; everything else — including `mslogon` from the DART case — is flagged. Joins to `DeviceFileEvents` to retrieve the DLL path and `FileProfile()` to confirm signing state.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
mitreTechniques: ["T1556.008","T1547.005"]
title: "Suspicious Network Provider DLL registered on {{DeviceName}}"
severity: "high"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Network providers run inside Winlogon and can capture cleartext credentials at sign-in via NPLogonNotify / NPPasswordChangeNotify. Isolate the host, capture the DLL, reset credentials for every account that signed in since the registry change, and audit the Services\\<name>\\NetworkProvider key on peer machines."
adaptation_notes: "AH-native. Two-stage: first build the suspicious-provider list from ProviderOrder, then resolve each per-service ProviderPath. webclient is added to the default exclusion because it ships with WebDAV-enabled Windows servers."
-->
```kql
// Suspicious Network Provider DLL registration — adapted from DART blog (2026-05-12)
let lookback = 30d;
let defaults = dynamic(["rdpnp","lanmanworkstation","webclient"]);
let SuspiciousProviders =
    DeviceRegistryEvents
    | where Timestamp > ago(lookback)
    | where RegistryKey has @"\Control\NetworkProvider\Order"
    | where RegistryValueName =~ "ProviderOrder"
    | extend Providers = split(RegistryValueData, ",")
    | mv-expand Provider = Providers to typeof(string)
    | extend Provider = tolower(trim(@"\s", Provider))
    | where isnotempty(Provider) and Provider !in~ (defaults)
    | distinct Provider;
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where RegistryKey has_all (@"\Services\", @"\NetworkProvider")
| where RegistryValueName =~ "ProviderPath"
| extend Provider = tolower(extract(@"\\Services\\([^\\]+)\\NetworkProvider", 1, RegistryKey))
| where Provider in~ (SuspiciousProviders)
| extend DllPath = tolower(replace_string(replace_string(RegistryValueData, "%SystemRoot%", @"C:\Windows"), "%windir%", @"C:\Windows"))
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | extend DllPath = tolower(FolderPath)
    | project DeviceName, SHA1, DllPath
) on DeviceName, DllPath
| invoke FileProfile(SHA1, 1000)
| where isempty(SHA1) or SignatureState in~ ("SignedInvalid","Unsigned")
| project Timestamp, DeviceName, Provider, DllPath, SHA1, Signer, SignatureState, IsExecutable, GlobalPrevalence, RegistryValueData
| order by Timestamp desc
```

---

## Query 3: Unsigned DLL Loaded by LSASS as Notification Package or Network Provider

Complementary load-side detection. `lsass.exe` and `winlogon.exe` legitimately load notification-package and network-provider DLLs at boot; an unsigned or invalid-signature DLL loaded by either process — especially from a non-`System32` path — is a strong credential-theft signal. Particularly valuable on hosts where the registry-write event was not captured (host enrolled after install, or `passms` / `mslogon` registered prior to lookback).

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "CredentialAccess"
mitreTechniques: ["T1556.002","T1556.008"]
title: "Unsigned DLL loaded by LSASS or Winlogon on {{DeviceName}}"
severity: "high"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Capture the DLL, validate the file path against system-baseline DLLs, and treat as credential interception if the DLL exports NPLogonNotify, NPPasswordChangeNotify, or PasswordFilter."
adaptation_notes: "AH-native. ImageLoad telemetry can be high-volume; FileProfile + tight InitiatingProcessFileName filter keeps it bounded. ASR rule 'Block credential stealing from LSASS' will not catch DLLs loaded as registered notification packages — this query is the complement."
-->
```kql
// Unsigned auth-extension DLL loaded by LSASS / Winlogon
let lookback = 30d;
DeviceImageLoadEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("lsass.exe","winlogon.exe")
| where FileName endswith ".dll"
| where isnotempty(SHA1)
| summarize arg_min(Timestamp, *) by DeviceId, SHA1, FolderPath
| invoke FileProfile(SHA1, 1000)
| where SignatureState in~ ("Unsigned","SignedInvalid")
| where FolderPath !startswith @"c:\windows\winsxs\"  // tolerate Microsoft side-by-side store
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA1, Signer, SignatureState, GlobalPrevalence
| order by Timestamp desc
```

---

## Query 4: HPE Operations Agent Spawning Script Interpreters

The DART case showed `abc003.vbs` and follow-on tooling executed via HPE OA process tree. HPE OA legitimately runs scripted policies, but spawning `cscript.exe` / `wscript.exe` / `powershell.exe` / `cmd.exe` from `opcacta.exe` / `opcle.exe` (action / launcher agents) is rare in steady-state and worth review on every occurrence. Mirrors the generic "monitoring agent spawning interpreter" pattern but anchored on the specific HPE binaries.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
mitreTechniques: ["T1199","T1059.001","T1059.005"]
title: "HPE Operations Agent spawned script interpreter on {{DeviceName}}"
severity: "medium"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Validate with the HPOM operator team whether the policy / scheduled job is sanctioned. Compare against the third-party IT provider's change log. Examine the child process command line, the spawned script content, and any subsequent DLL drop or registry write within 1 hour on the same host."
adaptation_notes: "HPE OA binary set is documented (opcacta, opcle, opcmona, opcmsga, ovbbccb, opcjmd, opc). If your environment uses HP OpenView under a different binary name, add it. Generic parent-folder filter is the safety net."
-->
```kql
// HPE OA / HPOM spawning script interpreter
let lookback = 30d;
let hpeAgents = dynamic([
    "opcacta.exe","opcle.exe","opcmona.exe","opcmsga.exe","opcmsgi.exe",
    "ovbbccb.exe","opcjmd.exe","opc.exe","opcgeni.exe","opceca.exe","ovconfd.exe"
]);
let interpreters = dynamic(["cscript.exe","wscript.exe","powershell.exe","pwsh.exe","cmd.exe","mshta.exe"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (interpreters)
| where InitiatingProcessFileName in~ (hpeAgents)
    or InitiatingProcessFolderPath has_any (@"\hp\hp bto software", @"\hp openview", @"\hpbsm", @"\hpoa", @"\hp\hpoa")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine, ProcessId, InitiatingProcessId
| order by Timestamp desc
```

---

## Query 5: VBScript Discovery and External-IP Reconnaissance

DART reported `abc003.vbs` performing system network configuration discovery, AD discovery, and **external IP discovery via PowerShell** chained from VBScript. This query catches the chain regardless of parent process — `cscript.exe` or `wscript.exe` running a `.vbs` from a writable path, that then spawns `powershell.exe` reaching a public-IP-lookup service.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Join-based hunt across two DeviceProcessEvents windows in a single timeline — works in AH and Data Lake but exceeds NRT constraints. For CD, split into two narrower rules: (a) cscript/wscript running .vbs from C:\\Users\\Public, C:\\ProgramData, or C:\\Windows\\Temp; (b) powershell child of cscript/wscript invoking Invoke-WebRequest / Invoke-RestMethod against ifconfig.me, api.ipify.org, icanhazip.com, ipinfo.io, checkip.amazonaws.com."
-->
```kql
// VBScript -> PowerShell -> public-IP-lookup chain (T1016 + T1059.005 + T1059.001)
let lookback = 30d;
let ipLookupHosts = dynamic([
    "ifconfig.me","ifconfig.co","api.ipify.org","icanhazip.com","ipinfo.io",
    "checkip.amazonaws.com","myexternalip.com","ipecho.net","wtfismyip.com","ident.me"
]);
let suspiciousVbs =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ ("cscript.exe","wscript.exe")
    | where ProcessCommandLine has ".vbs"
    | project VbsTime=Timestamp, DeviceId, DeviceName, VbsCmd=ProcessCommandLine,
              VbsParent=InitiatingProcessFileName, VbsParentPath=InitiatingProcessFolderPath,
              ScriptProcessId=ProcessId;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (ipLookupHosts)
   or ProcessCommandLine has_any ("Invoke-WebRequest","Invoke-RestMethod","System.Net.WebClient","curl ","wget ")
| where InitiatingProcessFileName in~ ("cscript.exe","wscript.exe")
| join kind=inner suspiciousVbs on DeviceId, $left.InitiatingProcessId == $right.ScriptProcessId
| project Timestamp, DeviceName, VbsCmd, VbsParent, VbsParentPath, PSCmd=ProcessCommandLine, AccountName
| order by Timestamp desc
```

---

## Query 6: Web Shell Creation or Modification on IIS

DART observed `Errors.aspx` newly created and a **legitimate** `Signoff.aspx` modified to load `ghost.inc` from `%TEMP%`. Standard "new .aspx" hunts miss the second case. This query covers both: file-create / file-modify events under web roots where the writer is `w3wp.exe` (IIS) or a script interpreter, plus a hash-change signal on `Signoff.aspx`.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
mitreTechniques: ["T1505.003"]
title: "Suspicious web shell creation or modification on {{DeviceName}}"
severity: "high"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Isolate the web server, capture the modified or newly-created file, diff against source control or a known-good baseline, hunt for child processes of w3wp.exe (especially cmd.exe / powershell.exe) within 24h, and confirm whether the host is in HPE OA / HPOM scope."
adaptation_notes: "Filter on common IIS roots; extend FolderPath list if your environment uses non-default web roots. ActionType captures both Created and Modified; for known-good app-deployment writers (e.g., msdeploy.exe, deployment service accounts), add to the writer exclusion list."
-->
```kql
// Web shell create/modify on IIS — covers both new shells and modified-existing pages
let lookback = 30d;
let webRoots = dynamic([@"\inetpub\wwwroot", @"\inetpub\", @"\wwwroot\", @"\httpdocs\", @"\webapps\"]);
let knownNamesOfInterest = dynamic(["errors.aspx","signoff.aspx","ghost.inc","ghost.inf.aspx","updater.dll"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (webRoots)
   or tolower(FileName) in~ (knownNamesOfInterest)
| where FileName endswith ".aspx" or FileName endswith ".asp"
     or FileName endswith ".ashx" or FileName endswith ".asmx"
     or FileName endswith ".php"  or FileName endswith ".jsp"
     or FileName endswith ".inc"  or tolower(FileName) in~ (knownNamesOfInterest)
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","tomcat.exe","cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe")
    or InitiatingProcessFolderPath has_any (@"\hp\", @"\hpbsm\", @"\hpoa\", @"\hp openview")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

---

## Query 7: Credential Drop File Path Indicators

Highly specific path-based hunt for the staging files used by `mslogon.dll` and `passms.dll`. `C:\Users\Public\Music\` is not a legitimate write target for sign-in or password-change workflows. The `WindowsUpdateService` directory is an attacker masquerade and is **not** a real Windows directory.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
mitreTechniques: ["T1556.002","T1556.008"]
title: "Credential staging file created on {{DeviceName}}"
severity: "high"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Treat as active credential capture. Isolate the host, capture the file, reset every credential that signed in or changed password since the file was first written, and pivot to Queries 1 and 2 to find the registered DLL."
adaptation_notes: "AH-native. The masquerade path 'WindowsUpdateService' is high-fidelity (no legitimate Windows component uses this name). The C:\\Users\\Public\\Music\\abc123c.d filename pattern is from the published case — keep both the specific name and a permissive Users\\Public\\Music\\*.d wildcard."
-->
```kql
// Credential staging file paths from DART case
let lookback = 30d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where
       (FolderPath has @"\Users\Public\Music\" and (FileName endswith ".d" or tolower(FileName) == "abc123c.d"))
    or FolderPath has @"\ProgramData\WindowsUpdateService\"
    or (FolderPath has @"\ProgramData\" and tolower(FileName) == "ipd")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

---

## Query 8: Filename IOC Sweep (mslogon / passms / msupdate / ghost.inc / abc003)

Broad filename sweep across `DeviceFileEvents`, `DeviceImageLoadEvents`, and `DeviceProcessEvents`. These filenames are not published as hashes, but the names themselves are not part of any legitimate Microsoft, HPE, or major-vendor product, and `globalprevalence` on legitimate uses (if any) will be near-zero.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Union of three tables, useful for first-pass investigation but too broad for NRT/scheduled CD. For CD, split per-table and per-filename group: (a) DeviceFileEvents on FileName in~ list; (b) DeviceImageLoadEvents on FileName in~ (\"mslogon.dll\",\"passms.dll\",\"msupdate.dll\"); (c) DeviceProcessEvents on InitiatingProcessFileName or FileName in~ list. Names alone are weak indicators — pair with path or signing-state filters before going to CD."
-->
```kql
// Filename IOC sweep — DART trusted-third-party intrusion
let lookback = 30d;
let dllNames = dynamic(["mslogon.dll","passms.dll","msupdate.dll"]);
let allNames = dynamic(["mslogon.dll","passms.dll","msupdate.dll","abc003.vbs","errors.aspx","ghost.inc","ghost.inf.aspx","updater.dll","icon02.jpeg","abc123c.d"]);
let fileHits =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where tolower(FileName) in~ (allNames)
    | project Timestamp, DeviceName, Source="DeviceFileEvents", Name=FileName, Path=FolderPath, Action=ActionType,
              SHA256, InitProc=InitiatingProcessFileName, InitCmd=InitiatingProcessCommandLine;
let loadHits =
    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where tolower(FileName) in~ (dllNames)
    | project Timestamp, DeviceName, Source="DeviceImageLoadEvents", Name=FileName, Path=FolderPath, Action="ImageLoad",
              SHA256, InitProc=InitiatingProcessFileName, InitCmd=InitiatingProcessCommandLine;
let procHits =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where tolower(FileName) in~ (allNames) or tolower(InitiatingProcessFileName) in~ (allNames)
    | project Timestamp, DeviceName, Source="DeviceProcessEvents", Name=FileName, Path=FolderPath, Action="ProcessExec",
              SHA256, InitProc=InitiatingProcessFileName, InitCmd=InitiatingProcessCommandLine;
union fileHits, loadHits, procHits
| order by Timestamp desc
```

---

## Query 9: ngrok Execution and Tunnel Network Activity

DART observed `ngrok` deployed on internal servers (including SQL-01) for inbound RDP. This query catches both the **process** (binary renames included) and the **outbound tunnel network connections** that even a renamed ngrok cannot hide.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
mitreTechniques: ["T1572"]
title: "ngrok tunnel activity detected on {{DeviceName}}"
severity: "high"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Isolate the host. ngrok on an internal server with no documented business need is a high-fidelity indicator. Hunt for inbound RDP, WinRM, or SMB sessions originating from loopback / tunnel-egress addresses, and pivot to lateral-movement queries."
adaptation_notes: "ngrok rotates regional endpoints; the *.ngrok.io, *.ngrok-free.app, *.ngrok.app, *.ngrok.dev, and tunnel.us.ngrok.com endpoints are stable. Process-name detection catches default ngrok.exe; renamed binaries are caught by the network filter or by command-line signatures (authtoken, tcp 3389, tunnel start)."
-->
```kql
// ngrok execution + tunnel network activity
let lookback = 30d;
let ngrokDomains = dynamic(["ngrok.io","ngrok-free.app","ngrok.app","ngrok.dev","ngrok.com"]);
let procEvents =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where tolower(FileName) == "ngrok.exe"
         or ProcessCommandLine matches regex @"(?i)\bngrok(\.exe)?\b"
         or ProcessCommandLine has_all ("authtoken")
         or (ProcessCommandLine has "tcp" and ProcessCommandLine has "3389" and ProcessCommandLine has "tunnel")
    | project Timestamp, DeviceName, Source="Process",
              FileName, FolderPath, ProcessCommandLine, AccountName,
              InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
              RemoteUrl="", RemoteIP="";
let netEvents =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl has_any (ngrokDomains)
         or RemoteUrl matches regex @"(?i)\b[a-z0-9-]+\.ngrok(-free)?\.(io|app|dev|com)$"
    | project Timestamp, DeviceName, Source="Network",
              FileName=InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath,
              ProcessCommandLine=InitiatingProcessCommandLine, AccountName=InitiatingProcessAccountName,
              InitiatingProcessFileName="", InitiatingProcessFolderPath="", InitiatingProcessCommandLine="",
              RemoteUrl, RemoteIP;
union procEvents, netEvents
| order by Timestamp desc
```

---

## Query 10: WMI Remote Execution Spawning Tunnel Tools

DART reported WMI used to deploy and launch ngrok on additional internal devices from compromised web servers. `wmiprvse.exe` legitimately spawns many processes; the high-fidelity signal is `wmiprvse.exe` spawning a **tunneling tool or a process from a writable / non-standard path** within a short time of similar activity on another host.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
mitreTechniques: ["T1047","T1572"]
title: "WMI remote execution spawned tunnel/RAT-like process on {{DeviceName}}"
severity: "medium"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
recommendedActions: "Identify the originating host from the WMI event (DeviceProcessEvents InitiatingProcessRemoteIP if populated, or correlate against AlertEvidence). Confirm whether the spawned binary is sanctioned tooling. If unsanctioned, treat both source and destination hosts as compromised."
adaptation_notes: "wmiprvse.exe spawning powershell/cmd is common in legitimate inventory tooling. DISM is the largest source of FPs (dismhost.exe from C:\\Windows\\Temp\\{GUID}\\) — both are explicitly filtered in the query. The 'writable path .exe' branch will still pick up some installers and updaters; pair with FileProfile() / Signer == 'Microsoft Windows' as an additional exclusion before promoting to CD. The suspectChildNames branch (ngrok / frpc / chisel / plink / gost) is the high-fidelity core."
-->
```kql
// WMI spawning tunnel / RAT-like processes
let lookback = 30d;
let writablePaths = dynamic([@"\users\public\", @"\programdata\", @"\windows\temp\", @"\appdata\local\temp\"]);
let suspectChildNames = dynamic(["ngrok.exe","frpc.exe","frps.exe","chisel.exe","plink.exe","gost.exe"]);
// Common legitimate WMI-spawned MS binaries — DISM helpers, telemetry, etc.
let knownBenignChildNames = dynamic(["dismhost.exe","tiworker.exe","trustedinstaller.exe","taskhostw.exe","compattelrunner.exe","sppsvc.exe"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where tolower(FileName) !in~ (knownBenignChildNames)
| where not(FolderPath matches regex @"(?i)\\windows\\temp\\\{?[0-9a-f\-]{8,}\}?\\")  // DISM scratch dirs
| where tolower(FileName) in~ (suspectChildNames)
     or (FolderPath has_any (writablePaths) and FileName endswith ".exe" and FileName !endswith "msiexec.exe")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
          AccountName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## Query 11: Image-Masquerade Files Created Over SMB

`msupdate.dll` shipped encoded creds via SMB to a file named `icon02.jpeg`. Detects creation of image-extension files whose content / origin contradicts the extension — specifically, image files written from a service / system context to non-image directories, or image files written remotely via SMB by `System` from another host.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "DeviceFileEvents exposes remote SMB writes via RequestAccountName + RequestSourceIP (NOT InitiatingProcessRemoteIP, which is a DeviceNetworkEvents-only column). For CD, narrow to: ActionType == FileCreated + FileName endswith image-ext + FolderPath has \\C$\\ or \\admin$\\ or another share path + isnotempty(RequestSourceIP). Keep as investigation query for now."
-->
```kql
// Image-masquerade files written over SMB or to staging shares
let lookback = 30d;
let imageExts = dynamic([".jpeg",".jpg",".png",".gif",".bmp",".ico"]);
let knownNames = dynamic(["icon02.jpeg","icon02.jpg"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where tolower(FileName) in~ (knownNames)
     or (FileName has_any (imageExts)
         and (FolderPath has @"\$\" or FolderPath has @"\admin$\" or FolderPath has @"\c$\"
              or FolderPath has @"\ProgramData\WindowsUpdateService\"))
| where InitiatingProcessFileName in~ ("system","System","ntoskrnl.exe","")
     or isnotempty(RequestAccountName)
     or isnotempty(RequestSourceIP)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessAccountName, RequestAccountName, RequestSourceIP
| order by Timestamp desc
```

---

## Query 12: Correlated Defender Alerts for T1199 / Credential Interception

If Defender for Endpoint has already raised alerts for the related techniques (web shell, credential theft, suspicious LSA/notification-package modification, ngrok, WMI lateral movement), this query rolls them up per-device for fast triage. Acts as the "have we already detected this?" overview when starting from the article.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Alert correlation queries don't deploy as custom detections — they exist to summarize MDE-native detections. Use as the first triage query when responding to this article."
-->
```kql
// Correlated Defender alerts mapped to TTPs in the DART blog
let lookback = 30d;
let ttpKeywords = dynamic([
    "web shell","webshell","credential theft","credential stealing",
    "lsa","notification package","network provider","authentication package",
    "ngrok","tunnel","wmi","lateral movement","powershell empire","cobalt",
    "mimikatz","secretsdump","password filter","credential dump"
]);
AlertInfo
| where Timestamp > ago(lookback)
| where Title has_any (ttpKeywords) or Category has_any (ttpKeywords)
| join kind=inner (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | where EntityType in~ ("Machine","File","Process","User","Url")
    | project AlertId, EntityType, DeviceName, FileName, SHA256, AccountUpn, RemoteUrl
) on AlertId
| summarize
    AlertCount = dcount(AlertId),
    Severity   = make_set(Severity, 16),
    Titles     = make_set(Title, 16),
    Categories = make_set(Category, 8),
    Files      = make_set_if(FileName, isnotempty(FileName), 32),
    Users      = make_set_if(AccountUpn, isnotempty(AccountUpn), 32),
    Urls       = make_set_if(RemoteUrl, isnotempty(RemoteUrl), 32),
    FirstSeen  = min(Timestamp),
    LastSeen   = max(Timestamp)
    by DeviceName
| order by AlertCount desc, LastSeen desc
```

---

## General Tuning Notes

These apply regardless of environment — the rule of thumb is **path / signing / parentage**, not name alone:

| Query | What to tune in your environment |
|---|---|
| **Q1 (LSA Notification Packages)** | If your DCs run a third-party password-policy product (Specops, ManageEngine ADSelfService, Anixis PPE, nFront), the product DLL will appear here. Validate with the product vendor's documented DLL name, then add to `defaults`. Never blanket-exclude on filename — always require a **signed-by-known-publisher** check. |
| **Q2 (Network Provider DLLs)** | Citrix Workspace, Cisco AnyConnect VPN posture modules, some VDI agents, and OS-bundled add-ons (`p9np` on WSL hosts) all legitimately register network providers. Validate against the provider's publisher and add to the exclusion only after `FileProfile()` confirms a trusted signer. WebDAV (`webclient`) is already excluded. |
| **Q3 (Unsigned DLL into LSASS/Winlogon)** | Endpoint protection, DLP, and FIM products legitimately load DLLs into LSASS. Expect noise on day 1 from the agent's own DLLs — review `Signer` and add the trusted publisher to a session allowlist, do **not** name-allowlist. Filter `FolderPath !startswith @"c:\windows\winsxs\"` is already in the query; consider also tolerating `\program files\<knownEdrVendor>\`. |
| **Q4 (HPE OA → interpreter)** | If your operator team runs sanctioned VBScript / PowerShell policies via HPOM, expect baseline volume. Validate the child command line and the spawned script path against the HPOM policy library before excluding. Do not exclude by `AccountName` — the HPE OA service account is exactly what the attacker abuses. |
| **Q5 (VBScript → public IP lookup)** | Some legitimate tooling (asset inventory, geo-aware portals) calls public-IP APIs. The chain `cscript/wscript → PowerShell → ifconfig.me` is unusual; if it appears, attribute to a named script. |
| **Q6 (Web shell create/modify)** | App-deployment pipelines (msdeploy, Octopus, Azure DevOps agent) write `.aspx` files legitimately. Add the deployment service account or InitiatingProcessFileName to a writer allowlist. Modifications to existing files by `w3wp.exe` are always suspicious — w3wp should not be writing source. |
| **Q7 (Credential drop paths)** | `C:\Users\Public\Music\` and `C:\ProgramData\WindowsUpdateService\` should not see writes in any environment. If they do, treat the result as high-fidelity even before content inspection. The masquerade name `WindowsUpdateService` is not a real Windows component. |
| **Q8 (Filename sweep)** | Pure-name detection is the weakest control here — pair with path / signing checks. If a benign script in your environment happens to use one of these names, add the exact `FolderPath + Signer` combination to an allowlist, not the bare name. |
| **Q9 (ngrok)** | ngrok has legitimate use cases (sanctioned bug bounty, developer tunnels, demo environments). The high-fidelity branch is **server-class hosts** (DCs, SQL, file servers, web servers) running ngrok — add a device-tag filter (`DeviceCategory == 'Server'` or `OnboardingStatus has "server"`) if your environment carries developer workstations with sanctioned ngrok. The renamed-binary branch (regex on command line) catches most evasions. |
| **Q10 (WMI lateral movement)** | `wmiprvse.exe` legitimately spawns many child processes. The query intentionally limits child set; the "writable path .exe" branch will produce noise from installers and updaters — promote that branch to CD only after pairing with a signing-state check or hash allowlist. |
| **Q11 (image masquerade over SMB)** | False positives from Group Policy logon-script image distribution, SCCM application packages, and OneDrive sync. Add the writer process or the destination share path to an allowlist once attributed. |
| **Q12 (Defender alert rollup)** | The keyword list is broad on purpose — narrow to your priority categories when re-running for daily triage. |

### Telemetry & Coverage Caveats

- **EDR coverage gap.** DART explicitly notes the web servers in the case had **no EDR**. Queries 6 (web shell), 9 (ngrok), and 11 (SMB masquerade) will under-report when run only against onboarded hosts. Cross-reference with IIS logs (`W3CIISLog`), Sysmon if deployed, and firewall logs for outbound to `*.ngrok.*`.
- **Image load on DCs.** `DeviceImageLoadEvents` volume on domain controllers is high; Query 3 is bounded by `FileProfile()` and unsigned filter but may still produce hundreds of weekly events on first run. Triage by `GlobalPrevalence < 100` for the most novel DLLs first.
- **Registry write timing.** `passms` was added to `Notification Packages` only on **DC01 and DC02** in the DART case. If your detection misses the window (registry write outside lookback), Query 3 (image-load side) is the fallback.
- **Custom-detection deployment.** Queries marked `cd_ready: true` are ready for the `detection-authoring` skill. Queries marked `cd_ready: false` are investigation-only by design — joins, unions, or `invoke FileProfile()` arity exceed NRT constraints. See `.github/skills/detection-authoring/SKILL.md` for the NRT / scheduled-rule constraints reference.
- **Adapt to Sentinel Data Lake.** For >30d lookback or to avoid Advanced Hunting safety filters, change `Timestamp` → `Timestamp` (XDR-native tables retain the name in Data Lake) and remove `invoke FileProfile()` (not supported in Data Lake — substitute a join to a known-good signer table or accept the missing signing check).

---

## References

- [Microsoft Security Blog — Undermining the trust boundary: Investigating a stealthy intrusion through third-party compromise (DART, 2026-05-12)](https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/)
- [MITRE ATT&CK T1199 — Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
- [MITRE ATT&CK T1556.002 — Modify Authentication Process: Password Filter DLL](https://attack.mitre.org/techniques/T1556/002/)
- [MITRE ATT&CK T1556.008 — Modify Authentication Process: Network Provider DLL](https://attack.mitre.org/techniques/T1556/008/)
- [MITRE ATT&CK T1547.005 — Boot or Logon Autostart: Security Support Provider](https://attack.mitre.org/techniques/T1547/005/) (closely related Winlogon/LSA extensibility abuse pattern)
- [MITRE ATT&CK T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [Microsoft Learn — NPLogonNotify callback](https://learn.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify)
- [Microsoft Learn — PSAM_PASSWORD_FILTER_ROUTINE (PasswordFilter) callback](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nc-ntsecapi-psam_password_filter_routine)
