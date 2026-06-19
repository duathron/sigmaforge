# Sigmaforge backtest — run7 (PRECISION corpus enlarged with one more DARPA OpTC host group)

## What changed vs run6

The **recall** pass is byte-for-byte identical to run5/run6 (FIX B3 sub-technique recall). The ONLY change is the **precision (benign) corpus**: run6's combined corpus (COMISET real slice + NextronSystems/evtx-baseline + one OpTC host group AIA-201-225) is EXTENDED with **one more OpTC host group (AIA-101-125)** for VOLUME, to test whether more benign data clears more rules' precision floor. (Spoiler — see 'diminishing return' below: it barely does.)

OpTC (**FiveDirections/OpTC-data**, public domain / Distribution A) has a dedicated benign collection period (**Sept 17-23 2019**) across ~1000 real enterprise hosts BEFORE any red-team activity — every process-creation record there is benign BY CONSTRUCTION. The eCAR JSON (`object=PROCESS action=CREATE/START`) is reshaped by `scripts/build_optc_benign.py` into the SAME COMISET `_source` envelope the rest of the benign corpus uses, so the single `comiset.yaml` mapping + `project_event` path handle it uniformly.

### OpTC Image path-form caveat (read before trusting path-anchored precision)

OpTC eCAR does **not** record `Image` as a normal drive-letter path. Measured on this corpus (80276 OpTC PROCESS/CREATE events): **37354 (47%)** carry the **NT-device form** `\Device\HarddiskVolume1\...\foo.exe`, **41115 (51%)** carry a **bare basename** with no path separator (`PING.EXE`, `cmd.exe`), 1807 (2%) carry other forms (`\\?\C:\...`, `\SystemRoot\...`, `%SystemRoot%\...`), and **0 (0%)** carry a drive-letter `C:\...` path.

Consequence for selector matching against the OpTC slice:

- `Image|endswith: '\foo.exe'` selectors **fail to match the ~50% bare-basename events** — a bare basename has no leading separator, so `\foo.exe` never matches `FOO.EXE`. They still match the NT-device-form events (which end in `\foo.exe`).
- `Image|contains: 'C:'` / any drive-letter-anchored selector matches **none** of the OpTC slice (0 drive-letter paths).
- selectors keyed on `CommandLine` or `ParentImage` are unaffected by the Image form, which is why the precision-measurable count is legitimate (it is a coverage-floor count driven by CommandLine/parent_path presence, not by Image path shape).

This does **not** invalidate the precision-measurable count and **cannot inflate precision** — a path mismatch only means a rule fired LESS on benign data, i.e. fewer FPs were detected. But it means the precision **figures for path-anchored rules UNDERSTATE their true FP exposure** on this corpus: an `Image|endswith` rule that looks clean here would still have fired on the ~50% bare-basename events had OpTC recorded full paths. Treat path-anchored `precision@COMISET = 1.0` on the OpTC slice as a floor, not a guarantee.

- precision corpus: run5 baseline **17124** -> run6 **47507** -> run7 **97400** EID-1 (run7 added **+49893** OpTC benign-by-construction events over run6).
- precision-measurable rules: **8** / 609 loaded (cleared the precision floor on the enlarged corpus).
- precision floor: the manifest's `recommended_precision_floor` is **9740** (10% of the 97400-event corpus); the per-rule table below uses the generic **1000**-event floor, so "8/609 precision-measurable" against 1000 should NOT be read as stronger than it is — at the recommended 9740-event floor far fewer rules would clear it.

### Honest delta — diminishing return

Enlarging the benign corpus from **47507** (run6) to **97400** (run7) — roughly **2x** — moved precision-measurable rules from **7** (run6) to **8** (run7): **+1**. Doubling the OpTC volume barely moves the needle. The bottleneck is NOT benign volume but **field/behaviour diversity**: more of the same enterprise activity (and OpTC's NT-device/bare-basename Image form) does not add the selection-field combinations that would let more rules clear the floor. Path-anchored rules in particular gain nothing from more OpTC.

### Partial pull (honest scope)

This run is **NOT** the full OpTC benign week. The run7 enlargement intended ~5 host groups but pulled **only 1** (AIA-101-125) before the Google Drive fetch failed on the next file (`gdown: Failed to retrieve file url` — public-file throttling). Treat run7 as run6 **+ one additional host group**, not a full-week corpus.

### Acceptance gate (engine == scored, both corpora)

| corpus | engine fires | scored fires | title-drop | gate |
|---|---|---|---|---|
| attack | 1163 | 1163 | 0 | PASS |
| benign | 50417 | 50417 | 0 | PASS |

---

# Sigmaforge backtest report (COMISET)

_run hash (worker-invariant): `e6aad42bbb347b2735d4a91552c643b392f5b1dbbb63af572776a5112c2472eb`_

> Precision is **precision@COMISET**, measured on the benign corpus described below — not a general/cross-environment false-positive rate. Labels are NOISY ground truth (rule-pattern attributions, e.g. OneDrive.exe tagged as an ATT&CK technique), so a measured FP may be a mislabel. Recall is measured on the labeled native-EVTX attack corpora over PROCESS-CREATION events only (the loaded ruleset is 100% process_creation). Precision floor: 1000 evaluated events.
> **Recall method (FIX B):** recall is **per-technique, sub-technique-granular** — each rule is measured against only the attack events of its own ATT&CK (sub-)technique(s), NOT pooled over the whole corpus and NOT diluted by sibling sub-techniques. A rule tagged `T1059.001` is scored against `T1059.001` events ONLY (its `T1059.003` siblings are excluded); a rule with a bare parent tag `T1059` covers all `T1059.*` children. Rules with no technique tag, or whose tags match zero attack events in this corpus, are `unmeasured` (not 0). Recall-measurable rules: 338/609.

> **Precision tautology caveat (BLOCKER-2):** a rule showing precision = 1.0 with fp = 0 is only trustworthy if benign-labelled events actually matched its selection. Rules whose benign-corpus coverage held **zero benign exemplars** are flagged `no-benign-exemplars` below: their fp = 0 is true *by construction*, so precision = 1.0 carries **no false-positive signal** — it is not evidence of FP-resistance.

## Funnel
- candidate: 609
- loaded: 609
- stateless: 609
- fires: 8
- survives_fp: 1

## Per-rule

| rule | recall | precision@COMISET | tp | fp | events_evaluated | benign_events_evaluated | precision_signal |
|---|---|---|---|---|---|---|---|
| Powershell Token Obfuscation - Process Creation | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Windows Defender Tampering Via Wmic.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Greedy Compression Using Rar.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Wmiexec Default Powershell Command | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using ChangePK and SLUI | 0.003067484662576687 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PsExec Remote Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious ClickFix/FileFix Execution Pattern | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Arbitrary Command Execution Using Msdt.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Ping Hex IP | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Shell32 DLL Execution in Suspicious Directory | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Child Process Created as System | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 16465 | 16303 | n/a (unmeasured) |
| Suspicious Child Process Of BgInfo.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Pypykatz Credentials Dumping Activity | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Devtoolslauncher.exe Executes Specified Binary | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Driver/DLL Installation Via Odbcconf.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using IEInstal - Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Child Process Of SQL Server | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Remote Access Tool - Renamed MeshAgent Execution - Windows | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Download and Execution Cradles | 0.00910179640718563 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Attempts of Kerberos Coercion Via DNS SPN Spoofing | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Windows Service Tampering | unmeasured (technique-0-events) | 0.0 | 0 | 66 | 97400 | 97238 | real |
| HackTool - Koadic Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Windows Internet Hosted WebDav Share Mount Via Net.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Doppelanger LSASS Dumper Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1 | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Mstsc.EXE Execution From Uncommon Parent | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File Download Via Bitsadmin To A Suspicious Target Folder | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| ImagingDevices Unusual Parent/Child Processes | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Suspicious Mofcomp Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Csc.EXE Execution Form Potentially Suspicious Parent | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharPersist Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious File Download From File Sharing Domain Via Wget.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File Download Using Notepad++ GUP Utility | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Base64 Encoded WMI Classes | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Using SettingSyncHost.exe as LOLBin | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Taskmgr as LOCAL_SYSTEM | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97043 | 96881 | n/a (unmeasured) |
| Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious PowerShell Parent Process | 0.0009874105159219946 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Xwizard.EXE Execution From Non-Default Location | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Remote CHM File Download/Execution Via HH.EXE | 0.010101010101010102 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SysmonEOP Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| ETW Trace Evasion Activity | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Speech Runtime Binary Child Process | 0.0006983240223463687 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Sensitive File Recovery From Backup Via Wbadmin.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Sensitive File Dump Via Print.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using Event Viewer RecentViews | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Arbitrary Code Execution Via Node.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential MsiExec Masquerading | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| CobaltStrike Load by Rundll32 | 0.011976047904191617 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Operator Bloopers Cobalt Strike Commands | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Service DACL Modification Via Set-Service Cmdlet | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| LSASS Process Reconnaissance Via Findstr.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| WhoAmI as Parameter | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Whoami.EXE Execution From Privileged Process | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97043 | 96881 | n/a (unmeasured) |
| Suspicious Serv-U Process Pattern | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - NSudo Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SafetyKatz Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed ProcDump Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential RDP Tunneling Via SSH | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Meterpreter/CobaltStrike Activity | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Tasks Folder Evasion | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Invoke-Obfuscation Via Stdin | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Sensitive File Dump Via Wbadmin.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3 | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious LNK Command-Line Padding with Whitespace Characters | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Taskkill Symantec Endpoint Protection | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Invoke-Obfuscation Via Use MSHTA | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Exchange PowerShell Snap-Ins Usage | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Potential Impacket Lateral Movement Activity | 0.0371900826446281 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential RDP Tunneling Via Plink | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| MMC Executing Files with Reversed Extensions Using RTLO Abuse | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Key Manager Access | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Download From File-Sharing Website Via Bitsadmin | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| RDP Connection Allowed Via Netsh.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Execution Of Non-Existing File | unmeasured (no-tag) | 0.0 | 0 | 41115 | 97400 | 97238 | real |
| Windows Defender Context Menu Removed | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Windows Credential Editor (WCE) Execution | 0.007042253521126761 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| PUA - AdFind Suspicious Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Web Access Feature Enabled Via DISM | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Base64 Encoded FromBase64String Cmdlet | 0.002221673660824488 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - RemoteKrbRelay Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Autorun Registry Modified via WMI | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Scheduled Task Creation Masquerading as System Processes | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Change Default File Association To Executable Via Assoc | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Boot Configuration Tampering Via Bcdedit.EXE | unmeasured (technique-0-events) | 1.0 | 34 | 0 | 97400 | 97238 | real |
| UAC Bypass Using MSConfig Token Modification - Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Tampering With Security Products Via WMIC | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious BitLocker Access Agent Update Utility Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Abusing Winsat Path Parsing - Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Velociraptor Child Process | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Sdiagnhost Calling Suspicious Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - winPEAS Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| System Restore Registry Modification via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Hacktool Execution - PE Metadata | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpLdapWhoami Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - CrackMapExec PowerShell Obfuscation | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Jusched.EXE Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Audit Policy Tampering Via Auditpol | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Abuse of Service Permissions to Hide Services Via Set-Service | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Disabled Volume Snapshots | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Reg Add BitLocker | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Disabled IE Security Features | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Certify Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Manipulation Of Default Accounts Via Net.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| WSL Kali-Linux Usage | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| WMI Backdoor Exchange Transport Agent | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious File Encoded To Base64 Via Certutil.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Remote Access Tool - AnyDesk Silent Installation | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Service DACL Abuse To Hide Services Via Sc.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Regsvr32 DLL Execution With Suspicious File Extension | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Scheduled Task Creation Involving Temp Folder | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Process Memory Dump via RdrLeakDiag.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Parent Double Extension File Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Base64 MZ Header In CommandLine | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - ADCSPwn Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious RDP Redirect Using TSCON | 1.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SharpMove Tool Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Seatbelt Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| VolumeShadowCopy Symlink Creation Via Mklink | 0.0014326647564469914 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Visual Basic Command Line Compiler Usage | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Odbcconf.EXE Suspicious DLL Location | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Ngrok Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Malicious PowerShell Commandlets - ProcessCreation | 0.007151370679380214 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious CertReq Command to Download | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious CustomShellHost Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Child Process of Notepad++ Updater - GUP.Exe | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential MSTSC Shadowing Activity | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - RedMimicry Winnti Playbook Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious DumpMinitool Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Audit Policy Tampering Via NT Resource Kit Auditpol | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious Regsvr32 HTTP IP Pattern | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Execution via stordiag.exe | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Imports Registry Key From an ADS | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Remotely Hosted HTA File Executed Via Mshta.EXE | 0.0038314176245210726 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File Decoded From Base64/Hex Via Certutil.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - CoercedPotato Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious Response File Execution Via Odbcconf.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4 | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious FileFix Execution Pattern | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious WmiPrvSE Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Invoke-Obfuscation VAR+ Launcher | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Empire PowerShell Launch Parameters | 0.0004937052579609973 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Email Exifiltration Via Powershell | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Advpack Call Via Rundll32.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SILENTTRINITY Stager Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Root Certificate Installed From Susp Locations | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Exports Critical Registry Keys To a File | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Rundll32 Execution Without Parameters | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - F-Secure C3 Load by Rundll32 | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File Encryption/Decryption Via Gpg4win From Suspicious Locations | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - KrbRelayUp Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Hacktool Execution - Imphash | 0.002425222312045271 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Unusual Child Process of dns.exe | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Curl Download And Execute Combination | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Script Interpreter Spawning Credential Scanner - Windows | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Cmd.EXE Missing Space Characters Execution Anomaly | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using Consent and Comctl32 - Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious JavaScript Execution Via Mshta.EXE | 0.007662835249042145 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Finger.EXE Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Execution With Potential Decryption Capabilities | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Powershell Defender Disable Scan Feature | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Use of CSharp Interactive Console | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential SMB Relay Attack Tool Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Uninstall Sysinternals Sysmon | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Wusa.EXE Executed By Parent Process Located In Suspicious Location | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Privilege Escalation via Service Permissions Weakness | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious SYSTEM User Process Creation | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Invoke-WebRequest Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious ShellExec_RunDLL Call Via Ordinal | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| PUA - DIT Snapshot Viewer | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PrintBrm ZIP Creation of Extraction | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| OneNote.EXE Execution of Malicious Embedded Scripts | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed MegaSync Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Remote SquiblyTwo Technique Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Credential Dumping Via LSASS Process Clone | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| ETW Logging Tamper In .NET Processes Via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| All Backups Deleted Via Wbadmin.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File With Suspicious Extension Downloaded Via Bitsadmin | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PPL Tampering Via WerFaultSecure | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious DLL Loaded via CertOC.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Default PowerSploit/Empire Scheduled Task Creation | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Tamper Windows Defender Remove-MpPreference | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Installation of WSL Kali-Linux | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Adplus.EXE Abuse | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Obfuscated PowerShell OneLiner Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| MSDT Execution Via Answer File | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| MMC20 Lateral Movement | 0.02066115702479339 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Add Insecure Download Source To Winget | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| DumpStack.log Defender Evasion | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Shadow Copies Deletion Using Operating Systems Utilities | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - XORDump Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Obfuscated PowerShell MSI Install via WindowsInstaller COM | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Command Patterns In Scheduled Task Creation | 0.00023353573096683791 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Script Interpreter Execution From Suspicious Folder | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| File Download Via Windows Defender MpCmpRun.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Program Names | 0.021796407185628742 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| User Shell Folders Registry Modification via CommandLine | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Renamed Rundll32 Execution | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Sysinternals Sdelete Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Execution Location Of Wermgr.EXE | unmeasured (no-tag) | 0.0 | 0 | 125 | 97400 | 97238 | real |
| Windows Credential Guard Registry Tampering Via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| OpenWith.exe Executes Specified Binary | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Disable Important Scheduled Task | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Kavremover Dropped Binary LOLBIN Usage | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious Child Processes Spawned by ConHost | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious File Download From IP Via Curl.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Processes Spawned by Java.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SharpWSUS/WSUSpendu Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Chopper Webshell Process Pattern | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Remote Access Tool - ScreenConnect Server Web Shell Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| ShimCache Flush | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Base64 Encoded Reflective Assembly Load | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - PurpleSharp Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Persistence Via Sticky Key Backdoor | 0.007751937984496124 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - DefenderCheck Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - 3Proxy Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - PowerTool Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Kerberos Ticket Request via CLI | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Dllhost.EXE Execution Anomaly | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Microsoft Office Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File Download with Headless Browser | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Covenant PowerShell Launcher | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspect Svchost Activity | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA- IOX Tunneling Tool Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Invoke-Obfuscation Via Use Clip | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed AutoIt Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Sysinternals PsSuspend Suspicious Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Data Stealing Via Chromium Headless Debugging | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| SQLite Firefox Profile Data DB Access | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious UltraVNC Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Impacket Tools Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Plink Port Forwarding | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UAC Bypass Using Disk Cleanup | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| RestrictedAdminMode Registry Value Tampering - ProcCreation | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious File Download From File Sharing Domain Via Curl.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Script Change Permission Via Set-Acl | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| DSInternals Suspicious PowerShell Cmdlets | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Chisel Tunneling Tool Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious AddinUtil.EXE CommandLine Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Inveigh Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed PingCastle Binary Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Copy From VolumeShadowCopy Via Cmd.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction' | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Mshtml.DLL RunHTMLApplication Suspicious Usage | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Bypass UAC via CMSTP | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Remote XSL Execution Via Msxsl.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Invoke-Obfuscation Obfuscated IEX Invocation | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Control Panel Items | 0.002150537634408602 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - TruffleSnout Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| DLL Sideloading by VMware Xfer Utility | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious HWP Sub Processes | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| NTLM Hash Leak Via Curl NTLM Authentication | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Malicious Base64 Encoded PowerShell Keywords in Command Lines | 0.0007405578869414959 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Credential Dumping Attempt Using New NetworkProvider - CLI | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Interactive AT Job | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Schtasks From Suspicious Folders | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - PCHunter Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious AgentExecutor PowerShell Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential LethalHTA Technique Execution | 0.02681992337164751 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Delete Important Scheduled Task | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Cscript/Wscript Uncommon Script Extension Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious PowerShell IEX Execution Patterns | 0.0029622315477659837 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Webshell Tool Reconnaissance Activity | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Persistence Via Powershell Search Order Hijacking - Task | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Wab Execution From Non Default Location | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Disable Windows Defender AV Security Monitoring | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Regsvr32 Execution From Highly Suspicious Location | 0.05660377358490566 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Mshta.EXE Execution Patterns | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential CobaltStrike Process Patterns | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process of AspNetCompiler | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Encoded PowerShell Command Line | 0.0017279684028634905 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| AADInternals PowerShell Cmdlets Execution - ProccessCreation | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| User Added to Remote Desktop Users Group | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Registry Modification From ADS Via Regini.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| CMSTP Execution Process Creation | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Ping/Del Command Combination | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Base64 Encoded PowerShell Command Detected | 0.0014811157738829918 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Sensitive File Access Via Volume Shadow Copy Backup | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious IIS Module Registration | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Base64 Encoded Invoke Keyword | 0.001974821031843989 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious Child Process Of Regsvr32 | 0.05660377358490566 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Empire PowerShell UAC Bypass | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Execution From Outlook Temporary Folder | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Wab/Wabmig Unusual Parent Or Child Processes | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Remote Access Tool - Anydesk Execution From Suspicious Folder | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious TSCON Start as SYSTEM | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97043 | 96881 | n/a (unmeasured) |
| ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - GMER Rootkit Detector and Remover Execution | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| File Download From IP Based URL Via CertOC.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - CrackMapExec Execution Patterns | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious PowerShell Download and Execute Pattern | 0.00740557886941496 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Uninstall of Windows Defender Feature via PowerShell | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| CreateDump Process Dump | 0.004464285714285714 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Child Process Of Veeam Dabatase | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Remote Child Process From Outlook | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Bypass UAC via WSReset.exe | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Double Extension File Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Enable LM Hash Storage - ProcCreation | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using PkgMgr and DISM | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Via Right-to-Left Override | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious PowerShell Mailbox Export to Share | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Windows Defender Definition Files Removed | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious DLL Registered Via Odbcconf.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Schtasks Execution AppData Folder | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Set Suspicious Files as System Files Using Attrib.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Arbitrary File Download Via IMEWDBLD.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential NTLM Coercion Via Certutil.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HKTL - SharpSuccessor Privilege Escalation Tool Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Arbitrary File Download Using Office Application | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious New Service Creation | 0.017361111111111112 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Service Path Modification | 0.001736111111111111 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Script Event Consumer Spawning Process | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HTML Help HH.EXE Suspicious Child Process | 0.0015734515806036333 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - CsExec Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Uncommon FileSystem Load Attempt By Format.com | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious ArcSOC.exe Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Download from Office Domain | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious PowerShell Encoded Command Patterns | 0.0007405578869414959 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Regedit as Trusted Installer | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Child Process Of Manage Engine ServiceDesk | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Rubeus Execution | 0.0016611295681063123 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass via ICMLuaUtil | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Chromium Browser Instance Executed With Custom Extension | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Debugger Registration Cmdline | 0.06976744186046512 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Redirection to Local Admin Share | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Data Exfiltration Activity Via CommandLine Tools | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential File Overwrite Via Sysinternals SDelete | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed BrowserCore.EXE Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Privilege Escalation via Named Pipe Impersonation | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Quarks PwDump Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential PowerShell Obfuscation Via WCHAR/CHAR | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious File Execution From Internet Hosted WebDav Share | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Dumping of Sensitive Hives Via Reg.EXE | 0.008695652173913044 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Cloudflared.EXE Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Terminal Service Process Spawn | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Hacktool - EDR-Freeze Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| TrustedPath UAC Bypass Pattern | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Uninstall Crowdstrike Falcon Sensor | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Office Binary Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Reg Add Suspicious Paths | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Microsoft IIS Connection Strings Decryption | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - CreateMiniDump Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Time Travel Debugging Utility Usage | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Rundll32 Invoking Inline VBScript | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Spool Service Child Process | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Deletion of Volume Shadow Copies via WMI with PowerShell | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Disable Windows IIS HTTP Logging | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Download From Direct IP Via Bitsadmin | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Calculator Usage | 0.001440922190201729 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Rundll32 Execution With DLL Stored In ADS | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Plink Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential WinAPI Calls Via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Process Masquerading As SvcHost.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Phishing Pattern ISO in Archive | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Outlook Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious WebDav Client Execution Via Rundll32.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Credential Dumping Via WER | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 16465 | 16303 | n/a (unmeasured) |
| Renamed AdFind Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Renamed Visual Studio Code Tunnel Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Service Registry Key Deleted Via Reg.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Wsudo Suspicious Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Schtasks Schedule Types | 0.0009341429238673517 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - LocalPotato Execution | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious Modification Of Scheduled Tasks | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| User Added To Highly Privileged Group | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Nimgrab Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| NtdllPipe Like Activity Execution | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| RunMRU Registry Key Deletion | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Registry Export of Third-Party Credentials | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Invoke-Obfuscation CLIP+ Launcher | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Shells Spawn by Java Utility Keytool | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential AMSI Bypass Via .NET Reflection | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Rundll32 Execution Without CommandLine Parameters | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Kernel Driver Utility (KDU) Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Hydra Password Bruteforce Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential CommandLine Path Traversal Via Cmd.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - EDRSilencer Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Desktopimgdownldr Command | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious Execution From Parent Process In Public Folder | 0.0009580838323353293 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using NTFS Reparse Point - Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| VMToolsd Suspicious Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Persistence Via Logon Scripts - CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed NirCmd.EXE Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Mpclient.DLL Sideloading Via Defender Binaries | 0.0 | 0.0 | 0 | 731 | 97400 | 97238 | real |
| Potential PowerShell Execution Policy Tampering - ProcCreation | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SharpChisel Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Powershell ReverseShell Connection | 0.00024685262898049864 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Python One-Liners with Base64 Decoding | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Curl.EXE Download | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - CrackMapExec Process Patterns | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97043 | 96881 | n/a (unmeasured) |
| Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Mavinject.EXE Execution | 0.25 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Binary In User Directory Spawned From Office Application | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - PPID Spoofing SelectMyParent Tool Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SharpImpersonation Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Winrs Local Command Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Fast Reverse Proxy (FRP) Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious HH.EXE Execution | 0.0012873694750393362 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| RDP Port Forwarding Rule Added Via Netsh.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| MpiExec Lolbin | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SOAPHound Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Findstr GPP Passwords | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Obfuscated PowerShell Code | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| MMC Spawning Windows Shell | 0.0371900826446281 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| DNS Exfiltration and Tunneling Tools Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Conhost.exe CommandLine Path Traversal | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - Mimikatz Execution | 0.005188067444876783 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Uncommon One Time Only Scheduled Task At 00:00 | 0.00023353573096683791 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Schtasks Creation Or Modification With SYSTEM Privileges | 0.0009341429238673517 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Dumpert Process Dumper Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using IDiagnostic Profile | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Defense Evasion Via Rename Of Highly Relevant Binaries | 0.004322766570605188 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Tampering With RDP Related Registry Keys Via Reg.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Scheduled Task Executing Encoded Payload from Registry | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Process Memory Dump Via Comsvcs.DLL | 0.0017857142857142857 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Htran/NATBypass Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - UACMe Akagi Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| HackTool - NetExec Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell SAM Copy | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Bad Opsec Defaults Sacrificial Processes With Improper Arguments | 0.001996007984031936 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious NTLM Authentication on the Printer Spooler Service | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Process Execution From Fake Recycle.Bin Folder | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| RunDLL32 Spawning Explorer | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Process Access via TrolleyExpress Exclusion | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Mstsc.EXE Execution With Local RDP File | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Windows AMSI Related Registry Tampering Via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential SSH Tunnel Persistence Install Using A Scheduled Task | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Memory Dump Mount Via MemProcFS | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PsExec/PAExec Escalation to LOCAL SYSTEM | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Net WebClient Casing Anomalies | 0.0014811157738829918 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential PowerShell Command Line Obfuscation | 0.0014811157738829918 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Uncommon Userinit Child Process | unmeasured (technique-0-events) | 0.0 | 0 | 181 | 97400 | 97238 | real |
| Security Privileges Enumeration Via Whoami.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Fsutil Suspicious Invocation | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Process Created Via Wmic.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed PAExec Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Windows Defender AV Bypass Via Dump64.EXE Rename | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Add SafeBoot Keys Via Reg Utility | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| LOL-Binary Copied From System Directory | 0.004322766570605188 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass WSReset | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Signing Bypass Via Windows Developer Features | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Kernel Dump Using Dtrace | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| SQLite Chromium Profile Data DB Access | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - WinPwn Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Execute Pcwrun.EXE To Leverage Follina | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Base64 Encoded IEX Cmdlet | 0.0012342631449024932 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - KrbRelay Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Control Panel DLL Load | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - NPS Tunneling Tool Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| HackTool - DInjector PowerShell Cradle Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Windows EventLog Autologger Session Registry Modification Via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Rundll32 Activity Invoking Sys File | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Devcon Execution Disabling VMware VMCI Device | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Crassus Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Rundll32 UNC Path Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Bloodhound/Sharphound Execution | 0.002554060956921505 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Network Reconnaissance Activity | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Outlook EnableUnsafeClientMailRules Setting Enabled | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Gpg.EXE Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| HackTool - SharpView Execution | 0.015873015873015872 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Privilege Escalation Using Symlink Between Osk and Cmd | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SharpDPAPI Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Process Execution From A Potentially Suspicious Folder | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Process Patterns NTDS.DIT Exfil | 0.0056657223796034 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Netcat Suspicious Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed CreateDump Utility Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed ZOHO Dctask64 Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Python Function Execution Security Warning Disabled In Excel | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Service Binary Directory | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Security Service Disabled Via Reg.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Rar Usage with Password and Compression Level | 0.0056022408963585435 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Processes Spawned by WinRM | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Non-privileged Usage of Reg or Powershell | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious MSHTA Child Process | 0.12643678160919541 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Privilege Escalation To LOCAL SYSTEM | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Regsvr32 Execution From Remote Share | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Mavinject Inject DLL Into Running Process | 0.16666666666666666 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Windows Shell/Scripting Processes Spawning Suspicious Programs | 0.004006104540251812 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Copying Sensitive Files with Credential Data | 0.0028653295128939827 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Delete All Scheduled Tasks | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Security Event Logging Disabled via MiniNt Registry Key - Process | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SharpUp PrivEsc Tool Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| MSHTA Execution with Suspicious File Extensions | 0.007662835249042145 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SharpEvtMute Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Recon Activity Using DriverQuery.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - PingCastle Execution From Potentially Suspicious Parent | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| System File Execution Location Anomaly | 0.008645533141210375 | 0.0 | 0 | 8161 | 97400 | 97238 | real |
| Renamed PsExec Service Execution | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential SysInternals ProcDump Evasion | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Sticky Key Like Backdoor Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Run PowerShell Script from ADS | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Splwow64 Without Params | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Forfiles.EXE Child Process Masquerading | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Whoami Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Tor Client/Browser Execution | 0.12167300380228137 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using Windows Media Player - Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Sysmon Driver Unloaded Via Fltmc.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Windows Update Agent Empty Cmdline | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed SysInternals DebugView Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| New ActiveScriptEventConsumer Created Via Wmic.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious MSDT Parent Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Microsoft OneNote Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File Download And Execution Via IEExec.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Hashcat Password Cracker Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious WMIC Execution Via Office Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Microsoft IIS Service Account Password Dumped | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Using DismHost | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Proxy Execution Via Wuauclt.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed NetSupport RAT Execution | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - RunXCmd Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Certipy Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious GoogleUpdate Child Process | unmeasured (no-tag) | 0.0 | 0 | 4 | 97400 | 97238 | real |
| Python Spawning Pretty TTY on Windows | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Sliver C2 Implant Activity Pattern | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Provlaunch.EXE Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - Stracciatella Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| UAC Bypass Tools Using ComputerDefaults | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Renamed Schtasks Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Child Process Of Wermgr.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Manage-bde.wsf Abuse To Proxy Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious Usage Of ShellExec_RunDLL | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Disabling Windows Defender WMI Autologger Session via Reg.exe | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - HandleKatz LSASS Dumper Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Suspicious File Download From IP Via Wget.EXE | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Chromium Browser Headless Execution To Mockbin Like Site | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Use of W32tm as Timer | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential Process Injection Via Msra.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential PowerShell Obfuscation Via Reversed Commands | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Rundll32 Registered COM Objects | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Bypass UAC via Fodhelper.exe | 0.003067484662576687 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Explorer NOUACCHECK Flag | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential LSASS Process Dump Via Procdump | 0.007142857142857143 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Powershell Base64 Encoded MpPreference Cmdlet | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Operator Bloopers Cobalt Strike Modules | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Run PowerShell Script from Redirected Input Stream | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - WSASS Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 15092 | 15092 | n/a (unmeasured) |
| Abused Debug Privilege by Arbitrary Parent Processes | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97043 | 96881 | n/a (unmeasured) |
| Webshell Detection With Command Line Keywords | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious File Download From IP Via Wget.EXE - Paths | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - SecurityXploded Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Uncommon Child Process Of Setres.EXE | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| LSASS Dump Keyword In CommandLine | 0.051643192488262914 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Raccine Uninstall | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| CMSTP UAC Bypass via COM Object Access | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| SafeBoot Registry Key Deleted Via Reg.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - AdvancedRun Suspicious Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - CleanWipe Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious Event Viewer Child Process | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Uncommon Svchost Command Line Parameter | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious Office Document Executed From Trusted Location | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - CrackMapExec Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potentially Suspicious Call To Win32_NTEventlogFile Class | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Eventlog Clearing or Configuration Change Activity | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Msdt.EXE Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Potential Crypto Mining Activity | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Execution of Powershell Script in Public Folder | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Set-Acl On Windows Folder | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Active Directory Database Snapshot Via ADExplorer | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Possible Privilege Escalation via Weak Service Permissions | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| UEFI Persistence Via Wpbbin - ProcessCreation | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious GrpConv Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Potential PowerShell Execution Via DLL | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Invoke-Obfuscation STDIN+ Launcher | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Vulnerable Driver Blocklist Registry Tampering Via CommandLine | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Execution via WorkFolders.exe | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Rundll32 Execution With Image Extension | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Process By Web Server Process | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Kernel Memory Dump Via LiveKD | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PowerShell Get-Process LSASS | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Renamed Vmnat.exe Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 17124 | 16962 | n/a (unmeasured) |
| Suspicious GUP Usage | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| HackTool - HollowReaper Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Webshell Hacking Activity Patterns | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious PowerShell Parameter Substring | 0.017032831399654405 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| File In Suspicious Location Encoded To Base64 Via Certutil.EXE | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| New User Created Via Net.EXE With Never Expire Option | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| Suspicious Process Parents | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PsExec Service Child Process Execution as LOCAL SYSTEM | unmeasured (no-tag) | unmeasured (no-benign-exemplars) | 0 | 0 | 97043 | 96881 | n/a (unmeasured) |
| PUA - Restic Backup Tool Execution | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - NirCmd Execution As LOCAL SYSTEM | 0.0 | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |
| PUA - Rclone Execution | unmeasured (technique-0-events) | unmeasured (no-benign-exemplars) | 0 | 0 | 97400 | 97238 | n/a (unmeasured) |

## FP-tuning candidates (over-broad on real traffic)
- **Execution Of Non-Existing File** catches the attack but fires 41115x on benign activity — candidate for tightening.
- **System File Execution Location Anomaly** catches the attack but fires 8161x on benign activity — candidate for tightening.
- **Potential Mpclient.DLL Sideloading Via Defender Binaries** catches the attack but fires 731x on benign activity — candidate for tightening.
- **Uncommon Userinit Child Process** catches the attack but fires 181x on benign activity — candidate for tightening.
- **Suspicious Execution Location Of Wermgr.EXE** catches the attack but fires 125x on benign activity — candidate for tightening.
- **Suspicious Windows Service Tampering** catches the attack but fires 66x on benign activity — candidate for tightening.

## Precision tautologies (no benign exemplars — precision carries no FP signal)
- none (every measured rule had at least one benign exemplar)