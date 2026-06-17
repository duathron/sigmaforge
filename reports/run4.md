# Sigmaforge backtest — run4 (FIX B: per-technique recall)

## FIX B — recall is now PER-TECHNIQUE

run3 pooled recall over the whole process-creation attack corpus (`tp / 1533`). A single-technique rule can match at most the events of its own technique, so a corpus-wide denominator caps its recall near **1.6%** by construction — a recall-side tautology that makes the number meaningless.

run4 measures each rule against **only the attack events of its own ATT&CK technique(s)**: `recall = (unique events of the rule's technique it fired on) / (total events of that technique)`. Sub-techniques fold to parent (T1543.003 -> T1543). Rules with no technique tag, or whose technique has zero attack events in the corpus, are **`unmeasured`** (NOT 0, NOT pooled).

- **rule -> technique coverage:** 555/609 loaded rules carry a usable `attack.tXXXX` tag.
- **recall-measurable rules:** 280/609 (technique present in the corpus); **unmeasured:** 329.

### Corpus switch (honestly disclosed)

Per-event TECHNIQUE labels require a technique-foldered corpus. sbousseaden `EVTX-ATTACK-SAMPLES` (run3's recall corpus) is foldered by **tactic** only and embeds a technique ID in just **3/278** filenames — it cannot be mapped to per-event technique granularity. The recall corpus is therefore switched to **mdecrevoisier/EVTX-to-MITRE-Attack** (CC0), foldered `TAxxxx/Txxxx`, so each source EVTX file's parent folder is an unambiguous ATT&CK technique. **Precision (the benign corpus) is UNCHANGED.**

- per-technique corpus: **1214** process-creation events across **31** techniques; **279** EVTX files mapped to a technique, **14** unmappable (non-`TAxxxx`-foldered helper dirs — excluded, NOT silently counted).
- technique skew (HONEST): the corpus is dominated by `T1027`=742, `T1059`=198, `T1021`=50, `T1070`=29, `T1003`=28 — recall for low-population techniques rests on very few events.
- event identity: per-event technique is keyed on `_stable_event_id` (fix C); a fire is joined to its technique via `OriginalLogfile` (EVTX basename) -> technique (`scripts/build_technique_map.py`, `data/comiset/technique_map.json`).

### Acceptance gate (engine == scored, both corpora)

| corpus | engine fires | scored fires | title-drop | gate |
|---|---|---|---|---|
| attack | 17 | 17 | 0 | PASS |
| benign | 100 | 100 | 0 | PASS |

---

# Sigmaforge backtest report (COMISET)

_run hash (worker-invariant): `15de32eefa232f025746b5be131c1e7d84e4b1673ca5dca479b923060d4f6939`_

> Precision is **precision@COMISET**, measured on the benign corpus described below — not a general/cross-environment false-positive rate. Labels are NOISY ground truth (rule-pattern attributions, e.g. OneDrive.exe tagged as an ATT&CK technique), so a measured FP may be a mislabel. Recall is measured on the labeled native-EVTX attack corpora over PROCESS-CREATION events only (the loaded ruleset is 100% process_creation). Precision floor: 1000 evaluated events.
> **Recall method (FIX B):** recall is **per-technique** — each rule is measured against only the attack events of its own ATT&CK technique(s) (denom = events of that technique, sub-technique folded to parent), NOT pooled over the whole corpus. Rules with no technique tag, or whose technique has zero attack events in this corpus, are `unmeasured` (not 0). Recall-measurable rules: 280/609.

> **Precision tautology caveat (BLOCKER-2):** a rule showing precision = 1.0 with fp = 0 is only trustworthy if benign-labelled events actually matched its selection. Rules whose benign-corpus coverage held **zero benign exemplars** are flagged `no-benign-exemplars` below: their fp = 0 is true *by construction*, so precision = 1.0 carries **no false-positive signal** — it is not evidence of FP-resistance.

## Funnel
- candidate: 609
- loaded: 609
- stateless: 609
- fires: 2
- survives_fp: 1

## Per-rule

| rule | recall | precision@COMISET | tp | fp | events_evaluated | benign_events_evaluated | precision_signal |
|---|---|---|---|---|---|---|---|
| Powershell Token Obfuscation - Process Creation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Windows Defender Tampering Via Wmic.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Greedy Compression Using Rar.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Wmiexec Default Powershell Command | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using ChangePK and SLUI | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PsExec Remote Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious ClickFix/FileFix Execution Pattern | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Arbitrary Command Execution Using Msdt.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Ping Hex IP | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Shell32 DLL Execution in Suspicious Directory | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process Created as System | 0.0 | unmeasured | 0 | 0 | 16465 | 16303 | n/a (unmeasured) |
| Suspicious Child Process Of BgInfo.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Pypykatz Credentials Dumping Activity | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Devtoolslauncher.exe Executes Specified Binary | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Driver/DLL Installation Via Odbcconf.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using IEInstal - Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process Of SQL Server | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Remote Access Tool - Renamed MeshAgent Execution - Windows | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Download and Execution Cradles | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Attempts of Kerberos Coercion Via DNS SPN Spoofing | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Windows Service Tampering | unmeasured | 0.0 | 0 | 66 | 17124 | 16962 | real |
| HackTool - Koadic Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Windows Internet Hosted WebDav Share Mount Via Net.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Doppelanger LSASS Dumper Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1 | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Mstsc.EXE Execution From Uncommon Parent | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Download Via Bitsadmin To A Suspicious Target Folder | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| ImagingDevices Unusual Parent/Child Processes | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Suspicious Mofcomp Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Csc.EXE Execution Form Potentially Suspicious Parent | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharPersist Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Download From File Sharing Domain Via Wget.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Download Using Notepad++ GUP Utility | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Base64 Encoded WMI Classes | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Using SettingSyncHost.exe as LOLBin | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Taskmgr as LOCAL_SYSTEM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious PowerShell Parent Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Xwizard.EXE Execution From Non-Default Location | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Remote CHM File Download/Execution Via HH.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SysmonEOP Execution | 0.0 | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| ETW Trace Evasion Activity | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Speech Runtime Binary Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sensitive File Recovery From Backup Via Wbadmin.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sensitive File Dump Via Print.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using Event Viewer RecentViews | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Arbitrary Code Execution Via Node.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential MsiExec Masquerading | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| CobaltStrike Load by Rundll32 | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Operator Bloopers Cobalt Strike Commands | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Service DACL Modification Via Set-Service Cmdlet | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| LSASS Process Reconnaissance Via Findstr.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| WhoAmI as Parameter | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Whoami.EXE Execution From Privileged Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Serv-U Process Pattern | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - NSudo Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SafetyKatz Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed ProcDump Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential RDP Tunneling Via SSH | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Meterpreter/CobaltStrike Activity | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Tasks Folder Evasion | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Invoke-Obfuscation Via Stdin | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sensitive File Dump Via Wbadmin.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3 | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious LNK Command-Line Padding with Whitespace Characters | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Taskkill Symantec Endpoint Protection | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Invoke-Obfuscation Via Use MSHTA | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Exchange PowerShell Snap-Ins Usage | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Potential Impacket Lateral Movement Activity | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential RDP Tunneling Via Plink | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| MMC Executing Files with Reversed Extensions Using RTLO Abuse | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Key Manager Access | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Download From File-Sharing Website Via Bitsadmin | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| RDP Connection Allowed Via Netsh.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Execution Of Non-Existing File | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Windows Defender Context Menu Removed | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Windows Credential Editor (WCE) Execution | 0.0 | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| PUA - AdFind Suspicious Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Web Access Feature Enabled Via DISM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Base64 Encoded FromBase64String Cmdlet | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - RemoteKrbRelay Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Autorun Registry Modified via WMI | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Scheduled Task Creation Masquerading as System Processes | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Change Default File Association To Executable Via Assoc | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Boot Configuration Tampering Via Bcdedit.EXE | 0.0 | 1.0 | 34 | 0 | 17124 | 16962 | real |
| UAC Bypass Using MSConfig Token Modification - Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Tampering With Security Products Via WMIC | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious BitLocker Access Agent Update Utility Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Abusing Winsat Path Parsing - Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Velociraptor Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sdiagnhost Calling Suspicious Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - winPEAS Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| System Restore Registry Modification via CommandLine | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Hacktool Execution - PE Metadata | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpLdapWhoami Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - CrackMapExec PowerShell Obfuscation | 0.0010638297872340426 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Jusched.EXE Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Audit Policy Tampering Via Auditpol | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Abuse of Service Permissions to Hide Services Via Set-Service | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Disabled Volume Snapshots | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Reg Add BitLocker | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Disabled IE Security Features | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Certify Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Manipulation Of Default Accounts Via Net.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| WSL Kali-Linux Usage | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| WMI Backdoor Exchange Transport Agent | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Encoded To Base64 Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Remote Access Tool - AnyDesk Silent Installation | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Service DACL Abuse To Hide Services Via Sc.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Regsvr32 DLL Execution With Suspicious File Extension | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Scheduled Task Creation Involving Temp Folder | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Process Memory Dump via RdrLeakDiag.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Parent Double Extension File Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Base64 MZ Header In CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - ADCSPwn Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious RDP Redirect Using TSCON | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpMove Tool Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Seatbelt Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| VolumeShadowCopy Symlink Creation Via Mklink | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Visual Basic Command Line Compiler Usage | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Odbcconf.EXE Suspicious DLL Location | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Ngrok Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Malicious PowerShell Commandlets - ProcessCreation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious CertReq Command to Download | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious CustomShellHost Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process of Notepad++ Updater - GUP.Exe | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential MSTSC Shadowing Activity | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - RedMimicry Winnti Playbook Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious DumpMinitool Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Audit Policy Tampering Via NT Resource Kit Auditpol | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious Regsvr32 HTTP IP Pattern | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Execution via stordiag.exe | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Imports Registry Key From an ADS | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Remotely Hosted HTA File Executed Via Mshta.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Decoded From Base64/Hex Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - CoercedPotato Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious Response File Execution Via Odbcconf.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4 | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious FileFix Execution Pattern | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious WmiPrvSE Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Invoke-Obfuscation VAR+ Launcher | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Empire PowerShell Launch Parameters | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Email Exifiltration Via Powershell | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Advpack Call Via Rundll32.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SILENTTRINITY Stager Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Root Certificate Installed From Susp Locations | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Exports Critical Registry Keys To a File | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Rundll32 Execution Without Parameters | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - F-Secure C3 Load by Rundll32 | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Encryption/Decryption Via Gpg4win From Suspicious Locations | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - KrbRelayUp Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Hacktool Execution - Imphash | 0.0 | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Unusual Child Process of dns.exe | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Curl Download And Execute Combination | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Script Interpreter Spawning Credential Scanner - Windows | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Cmd.EXE Missing Space Characters Execution Anomaly | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using Consent and Comctl32 - Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious JavaScript Execution Via Mshta.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Finger.EXE Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Execution With Potential Decryption Capabilities | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Powershell Defender Disable Scan Feature | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Use of CSharp Interactive Console | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential SMB Relay Attack Tool Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uninstall Sysinternals Sysmon | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Wusa.EXE Executed By Parent Process Located In Suspicious Location | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Privilege Escalation via Service Permissions Weakness | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious SYSTEM User Process Creation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Invoke-WebRequest Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious ShellExec_RunDLL Call Via Ordinal | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - DIT Snapshot Viewer | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PrintBrm ZIP Creation of Extraction | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| OneNote.EXE Execution of Malicious Embedded Scripts | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed MegaSync Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Remote SquiblyTwo Technique Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Credential Dumping Via LSASS Process Clone | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| ETW Logging Tamper In .NET Processes Via CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| All Backups Deleted Via Wbadmin.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File With Suspicious Extension Downloaded Via Bitsadmin | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PPL Tampering Via WerFaultSecure | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious DLL Loaded via CertOC.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Default PowerSploit/Empire Scheduled Task Creation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Tamper Windows Defender Remove-MpPreference | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Installation of WSL Kali-Linux | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Adplus.EXE Abuse | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Obfuscated PowerShell OneLiner Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| MSDT Execution Via Answer File | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| MMC20 Lateral Movement | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Add Insecure Download Source To Winget | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| DumpStack.log Defender Evasion | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Shadow Copies Deletion Using Operating Systems Utilities | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - XORDump Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Obfuscated PowerShell MSI Install via WindowsInstaller COM | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Command Patterns In Scheduled Task Creation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Script Interpreter Execution From Suspicious Folder | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Download Via Windows Defender MpCmpRun.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Program Names | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| User Shell Folders Registry Modification via CommandLine | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Renamed Rundll32 Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Sysinternals Sdelete Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Execution Location Of Wermgr.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Windows Credential Guard Registry Tampering Via CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| OpenWith.exe Executes Specified Binary | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Disable Important Scheduled Task | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Kavremover Dropped Binary LOLBIN Usage | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious Child Processes Spawned by ConHost | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Download From IP Via Curl.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Processes Spawned by Java.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpWSUS/WSUSpendu Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Chopper Webshell Process Pattern | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Remote Access Tool - ScreenConnect Server Web Shell Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| ShimCache Flush | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Base64 Encoded Reflective Assembly Load | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - PurpleSharp Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Persistence Via Sticky Key Backdoor | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - DefenderCheck Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - 3Proxy Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - PowerTool Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Kerberos Ticket Request via CLI | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Dllhost.EXE Execution Anomaly | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Microsoft Office Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Download with Headless Browser | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Covenant PowerShell Launcher | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspect Svchost Activity | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA- IOX Tunneling Tool Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Invoke-Obfuscation Via Use Clip | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed AutoIt Execution | 0.0 | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Sysinternals PsSuspend Suspicious Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Data Stealing Via Chromium Headless Debugging | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| SQLite Firefox Profile Data DB Access | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious UltraVNC Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Impacket Tools Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Plink Port Forwarding | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using Disk Cleanup | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| RestrictedAdminMode Registry Value Tampering - ProcCreation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Download From File Sharing Domain Via Curl.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Script Change Permission Via Set-Acl | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| DSInternals Suspicious PowerShell Cmdlets | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Chisel Tunneling Tool Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious AddinUtil.EXE CommandLine Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Inveigh Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed PingCastle Binary Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Copy From VolumeShadowCopy Via Cmd.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction' | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Mshtml.DLL RunHTMLApplication Suspicious Usage | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Bypass UAC via CMSTP | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Remote XSL Execution Via Msxsl.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Invoke-Obfuscation Obfuscated IEX Invocation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Control Panel Items | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - TruffleSnout Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| DLL Sideloading by VMware Xfer Utility | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious HWP Sub Processes | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| NTLM Hash Leak Via Curl NTLM Authentication | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Malicious Base64 Encoded PowerShell Keywords in Command Lines | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Credential Dumping Attempt Using New NetworkProvider - CLI | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Interactive AT Job | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Schtasks From Suspicious Folders | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - PCHunter Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious AgentExecutor PowerShell Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential LethalHTA Technique Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Delete Important Scheduled Task | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Cscript/Wscript Uncommon Script Extension Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious PowerShell IEX Execution Patterns | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Webshell Tool Reconnaissance Activity | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Persistence Via Powershell Search Order Hijacking - Task | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Wab Execution From Non Default Location | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Disable Windows Defender AV Security Monitoring | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Regsvr32 Execution From Highly Suspicious Location | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Mshta.EXE Execution Patterns | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential CobaltStrike Process Patterns | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process of AspNetCompiler | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Encoded PowerShell Command Line | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| AADInternals PowerShell Cmdlets Execution - ProccessCreation | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| User Added to Remote Desktop Users Group | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Registry Modification From ADS Via Regini.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| CMSTP Execution Process Creation | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Ping/Del Command Combination | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Base64 Encoded PowerShell Command Detected | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sensitive File Access Via Volume Shadow Copy Backup | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious IIS Module Registration | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Base64 Encoded Invoke Keyword | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious Child Process Of Regsvr32 | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Empire PowerShell UAC Bypass | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Execution From Outlook Temporary Folder | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Wab/Wabmig Unusual Parent Or Child Processes | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Remote Access Tool - Anydesk Execution From Suspicious Folder | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious TSCON Start as SYSTEM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - GMER Rootkit Detector and Remover Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| File Download From IP Based URL Via CertOC.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - CrackMapExec Execution Patterns | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious PowerShell Download and Execute Pattern | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Uninstall of Windows Defender Feature via PowerShell | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| CreateDump Process Dump | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process Of Veeam Dabatase | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Remote Child Process From Outlook | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Bypass UAC via WSReset.exe | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Double Extension File Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Enable LM Hash Storage - ProcCreation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using PkgMgr and DISM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Via Right-to-Left Override | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious PowerShell Mailbox Export to Share | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Windows Defender Definition Files Removed | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious DLL Registered Via Odbcconf.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Schtasks Execution AppData Folder | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Set Suspicious Files as System Files Using Attrib.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Arbitrary File Download Via IMEWDBLD.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential NTLM Coercion Via Certutil.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HKTL - SharpSuccessor Privilege Escalation Tool Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Arbitrary File Download Using Office Application | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious New Service Creation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Service Path Modification | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Script Event Consumer Spawning Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HTML Help HH.EXE Suspicious Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - CsExec Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uncommon FileSystem Load Attempt By Format.com | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious ArcSOC.exe Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Download from Office Domain | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious PowerShell Encoded Command Patterns | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Regedit as Trusted Installer | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process Of Manage Engine ServiceDesk | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Rubeus Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass via ICMLuaUtil | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Chromium Browser Instance Executed With Custom Extension | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Debugger Registration Cmdline | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Redirection to Local Admin Share | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Data Exfiltration Activity Via CommandLine Tools | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential File Overwrite Via Sysinternals SDelete | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed BrowserCore.EXE Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Privilege Escalation via Named Pipe Impersonation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Quarks PwDump Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PowerShell Obfuscation Via WCHAR/CHAR | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Execution From Internet Hosted WebDav Share | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Dumping of Sensitive Hives Via Reg.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Cloudflared.EXE Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Terminal Service Process Spawn | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Hacktool - EDR-Freeze Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| TrustedPath UAC Bypass Pattern | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uninstall Crowdstrike Falcon Sensor | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Office Binary Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Reg Add Suspicious Paths | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Microsoft IIS Connection Strings Decryption | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - CreateMiniDump Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Time Travel Debugging Utility Usage | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Rundll32 Invoking Inline VBScript | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Spool Service Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Deletion of Volume Shadow Copies via WMI with PowerShell | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Disable Windows IIS HTTP Logging | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Download From Direct IP Via Bitsadmin | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Calculator Usage | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Rundll32 Execution With DLL Stored In ADS | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Plink Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential WinAPI Calls Via CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Process Masquerading As SvcHost.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Phishing Pattern ISO in Archive | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Outlook Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious WebDav Client Execution Via Rundll32.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Credential Dumping Via WER | 0.0 | unmeasured | 0 | 0 | 16465 | 16303 | n/a (unmeasured) |
| Renamed AdFind Execution | 0.0 | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Renamed Visual Studio Code Tunnel Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Service Registry Key Deleted Via Reg.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Wsudo Suspicious Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Schtasks Schedule Types | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - LocalPotato Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious Modification Of Scheduled Tasks | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| User Added To Highly Privileged Group | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Nimgrab Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| NtdllPipe Like Activity Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| RunMRU Registry Key Deletion | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Registry Export of Third-Party Credentials | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Invoke-Obfuscation CLIP+ Launcher | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Shells Spawn by Java Utility Keytool | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential AMSI Bypass Via .NET Reflection | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Rundll32 Execution Without CommandLine Parameters | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Kernel Driver Utility (KDU) Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Hydra Password Bruteforce Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential CommandLine Path Traversal Via Cmd.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - EDRSilencer Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Desktopimgdownldr Command | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious Execution From Parent Process In Public Folder | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using NTFS Reparse Point - Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| VMToolsd Suspicious Child Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Persistence Via Logon Scripts - CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed NirCmd.EXE Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Mpclient.DLL Sideloading Via Defender Binaries | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PowerShell Execution Policy Tampering - ProcCreation | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpChisel Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Powershell ReverseShell Connection | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Python One-Liners with Base64 Decoding | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Curl.EXE Download | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - CrackMapExec Process Patterns | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Mavinject.EXE Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Binary In User Directory Spawned From Office Application | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - PPID Spoofing SelectMyParent Tool Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpImpersonation Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Winrs Local Command Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Fast Reverse Proxy (FRP) Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious HH.EXE Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| RDP Port Forwarding Rule Added Via Netsh.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| MpiExec Lolbin | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SOAPHound Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Findstr GPP Passwords | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Obfuscated PowerShell Code | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| MMC Spawning Windows Shell | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| DNS Exfiltration and Tunneling Tools Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Conhost.exe CommandLine Path Traversal | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Mimikatz Execution | 0.03571428571428571 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uncommon One Time Only Scheduled Task At 00:00 | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Schtasks Creation Or Modification With SYSTEM Privileges | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Dumpert Process Dumper Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using IDiagnostic Profile | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Via Rename Of Highly Relevant Binaries | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Tampering With RDP Related Registry Keys Via Reg.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Scheduled Task Executing Encoded Payload from Registry | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Process Memory Dump Via Comsvcs.DLL | 0.07142857142857142 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Htran/NATBypass Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - UACMe Akagi Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| HackTool - NetExec Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell SAM Copy | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Bad Opsec Defaults Sacrificial Processes With Improper Arguments | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious NTLM Authentication on the Printer Spooler Service | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Process Execution From Fake Recycle.Bin Folder | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| RunDLL32 Spawning Explorer | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Process Access via TrolleyExpress Exclusion | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Mstsc.EXE Execution With Local RDP File | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Windows AMSI Related Registry Tampering Via CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential SSH Tunnel Persistence Install Using A Scheduled Task | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Memory Dump Mount Via MemProcFS | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PsExec/PAExec Escalation to LOCAL SYSTEM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Net WebClient Casing Anomalies | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PowerShell Command Line Obfuscation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uncommon Userinit Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Security Privileges Enumeration Via Whoami.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Fsutil Suspicious Invocation | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Process Created Via Wmic.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed PAExec Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Windows Defender AV Bypass Via Dump64.EXE Rename | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Add SafeBoot Keys Via Reg Utility | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| LOL-Binary Copied From System Directory | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass WSReset | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Signing Bypass Via Windows Developer Features | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Kernel Dump Using Dtrace | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| SQLite Chromium Profile Data DB Access | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - WinPwn Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Execute Pcwrun.EXE To Leverage Follina | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Base64 Encoded IEX Cmdlet | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - KrbRelay Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Control Panel DLL Load | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - NPS Tunneling Tool Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| HackTool - DInjector PowerShell Cradle Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Windows EventLog Autologger Session Registry Modification Via CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Rundll32 Activity Invoking Sys File | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Devcon Execution Disabling VMware VMCI Device | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Crassus Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Rundll32 UNC Path Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Bloodhound/Sharphound Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Network Reconnaissance Activity | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Outlook EnableUnsafeClientMailRules Setting Enabled | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Gpg.EXE Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpView Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Privilege Escalation Using Symlink Between Osk and Cmd | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpDPAPI Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Process Execution From A Potentially Suspicious Folder | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Process Patterns NTDS.DIT Exfil | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Netcat Suspicious Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed CreateDump Utility Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed ZOHO Dctask64 Execution | unmeasured | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Python Function Execution Security Warning Disabled In Excel | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Service Binary Directory | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Security Service Disabled Via Reg.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Rar Usage with Password and Compression Level | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Processes Spawned by WinRM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Non-privileged Usage of Reg or Powershell | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious MSHTA Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Privilege Escalation To LOCAL SYSTEM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Regsvr32 Execution From Remote Share | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Mavinject Inject DLL Into Running Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Windows Shell/Scripting Processes Spawning Suspicious Programs | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Copying Sensitive Files with Credential Data | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Delete All Scheduled Tasks | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Security Event Logging Disabled via MiniNt Registry Key - Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpUp PrivEsc Tool Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| MSHTA Execution with Suspicious File Extensions | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpEvtMute Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Recon Activity Using DriverQuery.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - PingCastle Execution From Potentially Suspicious Parent | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| System File Execution Location Anomaly | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed PsExec Service Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential SysInternals ProcDump Evasion | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sticky Key Like Backdoor Execution | 0.14285714285714285 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Run PowerShell Script from ADS | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Splwow64 Without Params | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Forfiles.EXE Child Process Masquerading | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Whoami Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Tor Client/Browser Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using Windows Media Player - Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sysmon Driver Unloaded Via Fltmc.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Windows Update Agent Empty Cmdline | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed SysInternals DebugView Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| New ActiveScriptEventConsumer Created Via Wmic.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious MSDT Parent Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Microsoft OneNote Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Download And Execution Via IEExec.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Hashcat Password Cracker Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious WMIC Execution Via Office Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Microsoft IIS Service Account Password Dumped | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using DismHost | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Proxy Execution Via Wuauclt.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed NetSupport RAT Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - RunXCmd Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Certipy Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious GoogleUpdate Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Python Spawning Pretty TTY on Windows | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Sliver C2 Implant Activity Pattern | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Provlaunch.EXE Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Stracciatella Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Tools Using ComputerDefaults | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Schtasks Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process Of Wermgr.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Manage-bde.wsf Abuse To Proxy Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Usage Of ShellExec_RunDLL | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Disabling Windows Defender WMI Autologger Session via Reg.exe | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - HandleKatz LSASS Dumper Execution | 0.0 | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious File Download From IP Via Wget.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Chromium Browser Headless Execution To Mockbin Like Site | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Use of W32tm as Timer | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Process Injection Via Msra.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PowerShell Obfuscation Via Reversed Commands | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Rundll32 Registered COM Objects | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Bypass UAC via Fodhelper.exe | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Explorer NOUACCHECK Flag | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential LSASS Process Dump Via Procdump | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Powershell Base64 Encoded MpPreference Cmdlet | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Operator Bloopers Cobalt Strike Modules | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Run PowerShell Script from Redirected Input Stream | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - WSASS Execution | 0.0 | unmeasured | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Abused Debug Privilege by Arbitrary Parent Processes | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Webshell Detection With Command Line Keywords | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Download From IP Via Wget.EXE - Paths | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SecurityXploded Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uncommon Child Process Of Setres.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| LSASS Dump Keyword In CommandLine | 0.03571428571428571 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Raccine Uninstall | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| CMSTP UAC Bypass via COM Object Access | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| SafeBoot Registry Key Deleted Via Reg.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - AdvancedRun Suspicious Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - CleanWipe Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious Event Viewer Child Process | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uncommon Svchost Command Line Parameter | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious Office Document Executed From Trusted Location | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - CrackMapExec Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potentially Suspicious Call To Win32_NTEventlogFile Class | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Eventlog Clearing or Configuration Change Activity | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Msdt.EXE Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Crypto Mining Activity | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Execution of Powershell Script in Public Folder | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Set-Acl On Windows Folder | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Active Directory Database Snapshot Via ADExplorer | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Possible Privilege Escalation via Weak Service Permissions | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UEFI Persistence Via Wpbbin - ProcessCreation | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious GrpConv Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PowerShell Execution Via DLL | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Invoke-Obfuscation STDIN+ Launcher | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Vulnerable Driver Blocklist Registry Tampering Via CommandLine | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Execution via WorkFolders.exe | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Rundll32 Execution With Image Extension | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Process By Web Server Process | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Kernel Memory Dump Via LiveKD | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PowerShell Get-Process LSASS | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Vmnat.exe Execution | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious GUP Usage | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - HollowReaper Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Webshell Hacking Activity Patterns | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious PowerShell Parameter Substring | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File In Suspicious Location Encoded To Base64 Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| New User Created Via Net.EXE With Never Expire Option | 0.0 | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Process Parents | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PsExec Service Child Process Execution as LOCAL SYSTEM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Restic Backup Tool Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - NirCmd Execution As LOCAL SYSTEM | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - Rclone Execution | unmeasured | unmeasured | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |

## FP-tuning candidates (over-broad on real traffic)
- **Suspicious Windows Service Tampering** catches the attack but fires 66x on benign activity — candidate for tightening.

## Precision tautologies (no benign exemplars — precision carries no FP signal)
- none (every measured rule had at least one benign exemplar)

## Per-technique recall — rules with recall > 0

| rule | technique(s) | recall | numer/denom |
|---|---|---|---|
| Sticky Key Like Backdoor Execution | T1546 | 0.1429 | 1/7 |
| Process Memory Dump Via Comsvcs.DLL | T1003 | 0.0714 | 2/28 |
| HackTool - Mimikatz Execution | T1003 | 0.0357 | 1/28 |
| LSASS Dump Keyword In CommandLine | T1003 | 0.0357 | 1/28 |
| HackTool - CrackMapExec PowerShell Obfuscation | T1027,T1059 | 0.0011 | 1/940 |
