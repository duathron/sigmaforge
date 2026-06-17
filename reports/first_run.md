# Sigmaforge backtest report (COMISET)

_run hash (worker-invariant): `20ab7c5ceb91a015794ee1b65f99757961b37a530a6dc792c4ca3b94999cb5ce`_

> Precision is **precision@COMISET**, measured on ONE university network (COMISET) — not a general/cross-environment false-positive rate. Labels are NOISY ground truth (rule-pattern attributions, e.g. OneDrive.exe tagged as an ATT&CK technique), so a measured FP may be a mislabel. Recall is measured on the labeled native-EVTX attack corpora. Precision floor: 1000 evaluated events.

## Funnel
- candidate: 609
- loaded: 609
- stateless: 609
- fires: 1
- survives_fp: 1

## Per-rule

| rule | recall | precision@COMISET | tp | fp | events_evaluated |
|---|---|---|---|---|---|
| Powershell Token Obfuscation - Process Creation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Windows Defender Tampering Via Wmic.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Greedy Compression Using Rar.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Wmiexec Default Powershell Command | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using ChangePK and SLUI | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potential PsExec Remote Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious ClickFix/FileFix Execution Pattern | 0.0 | unmeasured | 0 | 0 | 2032 |
| Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Arbitrary Command Execution Using Msdt.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Ping Hex IP | 0.0 | unmeasured | 0 | 0 | 2032 |
| Shell32 DLL Execution in Suspicious Directory | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process Created as System | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process Of BgInfo.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Pypykatz Credentials Dumping Activity | 0.0 | unmeasured | 0 | 0 | 2032 |
| Devtoolslauncher.exe Executes Specified Binary | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Driver/DLL Installation Via Odbcconf.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using IEInstal - Process | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potential Provisioning Registry Key Abuse For Binary Proxy Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process Of SQL Server | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Remote Access Tool - Renamed MeshAgent Execution - Windows | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Download and Execution Cradles | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Attempts of Kerberos Coercion Via DNS SPN Spoofing | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Windows Service Tampering | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Koadic Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Windows Internet Hosted WebDav Share Mount Via Net.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Doppelanger LSASS Dumper Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1 | 0.0 | unmeasured | 0 | 0 | 2032 |
| Mstsc.EXE Execution From Uncommon Parent | 0.0 | unmeasured | 0 | 0 | 2032 |
| File Download Via Bitsadmin To A Suspicious Target Folder | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| ImagingDevices Unusual Parent/Child Processes | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Suspicious Mofcomp Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Csc.EXE Execution Form Potentially Suspicious Parent | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharPersist Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Download From File Sharing Domain Via Wget.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| File Download Using Notepad++ GUP Utility | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Base64 Encoded WMI Classes | 0.0 | unmeasured | 0 | 0 | 2032 |
| Using SettingSyncHost.exe as LOLBin | 0.0 | unmeasured | 0 | 0 | 2032 |
| Taskmgr as LOCAL_SYSTEM | 0.0 | unmeasured | 0 | 0 | 2032 |
| Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious PowerShell Parent Process | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Xwizard.EXE Execution From Non-Default Location | 0.0 | unmeasured | 0 | 0 | 2032 |
| Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | 0.00045727350671620465 | unmeasured | 0 | 0 | 2032 |
| Remote CHM File Download/Execution Via HH.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SysmonEOP Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| ETW Trace Evasion Activity | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Speech Runtime Binary Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Sensitive File Recovery From Backup Via Wbadmin.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Sensitive File Dump Via Print.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using Event Viewer RecentViews | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Arbitrary Code Execution Via Node.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential MsiExec Masquerading | 0.0 | unmeasured | 0 | 0 | 2032 |
| CobaltStrike Load by Rundll32 | 0.0 | unmeasured | 0 | 0 | 2032 |
| Operator Bloopers Cobalt Strike Commands | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Service DACL Modification Via Set-Service Cmdlet | 0.0 | unmeasured | 0 | 0 | 2032 |
| LSASS Process Reconnaissance Via Findstr.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| WhoAmI as Parameter | 0.0 | unmeasured | 0 | 0 | 2032 |
| Whoami.EXE Execution From Privileged Process | 0.0003143755358673907 | unmeasured | 0 | 0 | 2032 |
| Suspicious Serv-U Process Pattern | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - NSudo Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SafetyKatz Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed ProcDump Execution | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potential RDP Tunneling Via SSH | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Meterpreter/CobaltStrike Activity | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Tasks Folder Evasion | 0.0 | unmeasured | 0 | 0 | 2032 |
| Invoke-Obfuscation Via Stdin | 0.0 | unmeasured | 0 | 0 | 2032 |
| Sensitive File Dump Via Wbadmin.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3 | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious LNK Command-Line Padding with Whitespace Characters | 0.0 | unmeasured | 0 | 0 | 2032 |
| Taskkill Symantec Endpoint Protection | 0.0 | unmeasured | 0 | 0 | 2032 |
| Invoke-Obfuscation Via Use MSHTA | 0.0 | unmeasured | 0 | 0 | 2032 |
| Exchange PowerShell Snap-Ins Usage | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Potential Impacket Lateral Movement Activity | 0.0002572163475278651 | unmeasured | 0 | 0 | 2032 |
| Potential RDP Tunneling Via Plink | 0.0 | unmeasured | 0 | 0 | 2032 |
| MMC Executing Files with Reversed Extensions Using RTLO Abuse | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Key Manager Access | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Download From File-Sharing Website Via Bitsadmin | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| RDP Connection Allowed Via Netsh.EXE | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Execution Of Non-Existing File | 0.0 | unmeasured | 0 | 0 | 2032 |
| Windows Defender Context Menu Removed | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Windows Credential Editor (WCE) Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| PUA - AdFind Suspicious Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Web Access Feature Enabled Via DISM | 0.0 | unmeasured | 0 | 0 | 2032 |
| RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Base64 Encoded FromBase64String Cmdlet | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - RemoteKrbRelay Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Autorun Registry Modified via WMI | 0.0 | unmeasured | 0 | 0 | 2032 |
| Scheduled Task Creation Masquerading as System Processes | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Change Default File Association To Executable Via Assoc | 0.0 | unmeasured | 0 | 0 | 2032 |
| Boot Configuration Tampering Via Bcdedit.EXE | 5.715918833952558e-05 | 1.0 | 34 | 0 | 2032 |
| UAC Bypass Using MSConfig Token Modification - Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Tampering With Security Products Via WMIC | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious BitLocker Access Agent Update Utility Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Abusing Winsat Path Parsing - Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Velociraptor Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Sdiagnhost Calling Suspicious Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - winPEAS Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| System Restore Registry Modification via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| Hacktool Execution - PE Metadata | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpLdapWhoami Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - CrackMapExec PowerShell Obfuscation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Jusched.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Audit Policy Tampering Via Auditpol | 0.0 | unmeasured | 0 | 0 | 2032 |
| Abuse of Service Permissions to Hide Services Via Set-Service | 0.0 | unmeasured | 0 | 0 | 2032 |
| Disabled Volume Snapshots | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Reg Add BitLocker | 0.0 | unmeasured | 0 | 0 | 2032 |
| Disabled IE Security Features | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Certify Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Manipulation Of Default Accounts Via Net.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| WSL Kali-Linux Usage | 0.0 | unmeasured | 0 | 0 | 2032 |
| WMI Backdoor Exchange Transport Agent | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Encoded To Base64 Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Remote Access Tool - AnyDesk Silent Installation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Service DACL Abuse To Hide Services Via Sc.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Regsvr32 DLL Execution With Suspicious File Extension | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Scheduled Task Creation Involving Temp Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| Process Memory Dump via RdrLeakDiag.EXE | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious Parent Double Extension File Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Base64 MZ Header In CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - ADCSPwn Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious RDP Redirect Using TSCON | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpMove Tool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Seatbelt Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| VolumeShadowCopy Symlink Creation Via Mklink | 0.0 | unmeasured | 0 | 0 | 2032 |
| Visual Basic Command Line Compiler Usage | 0.0 | unmeasured | 0 | 0 | 2032 |
| Odbcconf.EXE Suspicious DLL Location | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Ngrok Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Malicious PowerShell Commandlets - ProcessCreation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious CertReq Command to Download | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious CustomShellHost Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process of Notepad++ Updater - GUP.Exe | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential MSTSC Shadowing Activity | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - RedMimicry Winnti Playbook Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious DumpMinitool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Audit Policy Tampering Via NT Resource Kit Auditpol | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious Regsvr32 HTTP IP Pattern | 0.0 | unmeasured | 0 | 0 | 2032 |
| Execution via stordiag.exe | 0.0 | unmeasured | 0 | 0 | 2032 |
| Imports Registry Key From an ADS | 0.0 | unmeasured | 0 | 0 | 2032 |
| Remotely Hosted HTA File Executed Via Mshta.EXE | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| File Decoded From Base64/Hex Via Certutil.EXE | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - CoercedPotato Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Suspicious Response File Execution Via Odbcconf.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Downloaded From Direct IP Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4 | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious FileFix Execution Pattern | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious WmiPrvSE Child Process | 0.00011431837667905116 | unmeasured | 0 | 0 | 2032 |
| Invoke-Obfuscation VAR+ Launcher | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Empire PowerShell Launch Parameters | 0.0 | unmeasured | 0 | 0 | 2032 |
| Email Exifiltration Via Powershell | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Advpack Call Via Rundll32.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SILENTTRINITY Stager Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Root Certificate Installed From Susp Locations | 0.0 | unmeasured | 0 | 0 | 2032 |
| Exports Critical Registry Keys To a File | 0.0 | unmeasured | 0 | 0 | 2032 |
| Rundll32 Execution Without Parameters | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - F-Secure C3 Load by Rundll32 | 0.0 | unmeasured | 0 | 0 | 2032 |
| File Encryption/Decryption Via Gpg4win From Suspicious Locations | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - KrbRelayUp Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Hacktool Execution - Imphash | 5.715918833952558e-05 | unmeasured | 0 | 0 | 0 |
| Unusual Child Process of dns.exe | 0.0 | unmeasured | 0 | 0 | 2032 |
| Curl Download And Execute Combination | 0.0 | unmeasured | 0 | 0 | 2032 |
| Script Interpreter Spawning Credential Scanner - Windows | 0.0 | unmeasured | 0 | 0 | 2032 |
| Cmd.EXE Missing Space Characters Execution Anomaly | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using Consent and Comctl32 - Process | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious JavaScript Execution Via Mshta.EXE | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Finger.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Execution With Potential Decryption Capabilities | 0.0 | unmeasured | 0 | 0 | 2032 |
| Powershell Defender Disable Scan Feature | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Use of CSharp Interactive Console | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential SMB Relay Attack Tool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Uninstall Sysinternals Sysmon | 0.0 | unmeasured | 0 | 0 | 2032 |
| Wusa.EXE Executed By Parent Process Located In Suspicious Location | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Privilege Escalation via Service Permissions Weakness | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious SYSTEM User Process Creation | 0.0007144898542440697 | unmeasured | 0 | 0 | 2032 |
| Suspicious Invoke-WebRequest Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious ShellExec_RunDLL Call Via Ordinal | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - DIT Snapshot Viewer | 0.0 | unmeasured | 0 | 0 | 2032 |
| PrintBrm ZIP Creation of Extraction | 0.0 | unmeasured | 0 | 0 | 2032 |
| OneNote.EXE Execution of Malicious Embedded Scripts | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed MegaSync Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Remote SquiblyTwo Technique Execution | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| Potential Credential Dumping Via LSASS Process Clone | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| ETW Logging Tamper In .NET Processes Via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| All Backups Deleted Via Wbadmin.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| File With Suspicious Extension Downloaded Via Bitsadmin | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| PPL Tampering Via WerFaultSecure | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious DLL Loaded via CertOC.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Default PowerSploit/Empire Scheduled Task Creation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Tamper Windows Defender Remove-MpPreference | 0.0 | unmeasured | 0 | 0 | 2032 |
| Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location | 0.0 | unmeasured | 0 | 0 | 2032 |
| Installation of WSL Kali-Linux | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Adplus.EXE Abuse | 0.0 | unmeasured | 0 | 0 | 2032 |
| Obfuscated PowerShell OneLiner Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| MSDT Execution Via Answer File | 0.0 | unmeasured | 0 | 0 | 2032 |
| MMC20 Lateral Movement | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Add Insecure Download Source To Winget | 0.0 | unmeasured | 0 | 0 | 2032 |
| DumpStack.log Defender Evasion | 0.0 | unmeasured | 0 | 0 | 2032 |
| Shadow Copies Deletion Using Operating Systems Utilities | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - XORDump Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Obfuscated PowerShell MSI Install via WindowsInstaller COM | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Command Patterns In Scheduled Task Creation | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Script Interpreter Execution From Suspicious Folder | 0.00017147756501857672 | unmeasured | 0 | 0 | 2032 |
| File Download Via Windows Defender MpCmpRun.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Program Names | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| User Shell Folders Registry Modification via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Renamed Rundll32 Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Sysinternals Sdelete Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Execution Location Of Wermgr.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Windows Credential Guard Registry Tampering Via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| OpenWith.exe Executes Specified Binary | 0.0 | unmeasured | 0 | 0 | 2032 |
| Disable Important Scheduled Task | 0.0 | unmeasured | 0 | 0 | 2032 |
| Kavremover Dropped Binary LOLBIN Usage | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious Child Processes Spawned by ConHost | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Download From IP Via Curl.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Processes Spawned by Java.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpWSUS/WSUSpendu Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | 0.0 | unmeasured | 0 | 0 | 2032 |
| Chopper Webshell Process Pattern | 0.0 | unmeasured | 0 | 0 | 2032 |
| Remote Access Tool - ScreenConnect Server Web Shell Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| ShimCache Flush | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Base64 Encoded Reflective Assembly Load | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - PurpleSharp Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Persistence Via Sticky Key Backdoor | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - DefenderCheck Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - 3Proxy Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - PowerTool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Kerberos Ticket Request via CLI | 0.0 | unmeasured | 0 | 0 | 2032 |
| Dllhost.EXE Execution Anomaly | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Microsoft Office Child Process | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| File Download with Headless Browser | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Covenant PowerShell Launcher | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspect Svchost Activity | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| PUA- IOX Tunneling Tool Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Invoke-Obfuscation Via Use Clip | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed AutoIt Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Sysinternals PsSuspend Suspicious Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Data Stealing Via Chromium Headless Debugging | 0.0 | unmeasured | 0 | 0 | 2032 |
| SQLite Firefox Profile Data DB Access | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious UltraVNC Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Impacket Tools Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Plink Port Forwarding | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using Disk Cleanup | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| RestrictedAdminMode Registry Value Tampering - ProcCreation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Download From File Sharing Domain Via Curl.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Script Change Permission Via Set-Acl | 0.0 | unmeasured | 0 | 0 | 2032 |
| DSInternals Suspicious PowerShell Cmdlets | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Chisel Tunneling Tool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious AddinUtil.EXE CommandLine Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Inveigh Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed PingCastle Binary Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Copy From VolumeShadowCopy Via Cmd.EXE | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction' | 0.0 | unmeasured | 0 | 0 | 2032 |
| Mshtml.DLL RunHTMLApplication Suspicious Usage | 0.00020005715918833952 | unmeasured | 0 | 0 | 2032 |
| Bypass UAC via CMSTP | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Remote XSL Execution Via Msxsl.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Invoke-Obfuscation Obfuscated IEX Invocation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | 0.0 | unmeasured | 0 | 0 | 2032 |
| Control Panel Items | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - TruffleSnout Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| DLL Sideloading by VMware Xfer Utility | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious HWP Sub Processes | 0.0 | unmeasured | 0 | 0 | 2032 |
| NTLM Hash Leak Via Curl NTLM Authentication | 0.0 | unmeasured | 0 | 0 | 2032 |
| Malicious Base64 Encoded PowerShell Keywords in Command Lines | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Credential Dumping Attempt Using New NetworkProvider - CLI | 0.0 | unmeasured | 0 | 0 | 2032 |
| Interactive AT Job | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Schtasks From Suspicious Folders | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - PCHunter Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Suspicious AgentExecutor PowerShell Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential LethalHTA Technique Execution | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Delete Important Scheduled Task | 0.0 | unmeasured | 0 | 0 | 2032 |
| Cscript/Wscript Uncommon Script Extension Execution | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious PowerShell IEX Execution Patterns | 0.0 | unmeasured | 0 | 0 | 2032 |
| Webshell Tool Reconnaissance Activity | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Persistence Via Powershell Search Order Hijacking - Task | 0.0 | unmeasured | 0 | 0 | 2032 |
| Wab Execution From Non Default Location | 0.0 | unmeasured | 0 | 0 | 2032 |
| Disable Windows Defender AV Security Monitoring | 0.0 | unmeasured | 0 | 0 | 2032 |
| Regsvr32 Execution From Highly Suspicious Location | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Mshta.EXE Execution Patterns | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potential CobaltStrike Process Patterns | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process of AspNetCompiler | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Encoded PowerShell Command Line | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| AADInternals PowerShell Cmdlets Execution - ProccessCreation | 0.0 | unmeasured | 0 | 0 | 2032 |
| IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI | 0.0 | unmeasured | 0 | 0 | 2032 |
| User Added to Remote Desktop Users Group | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Registry Modification From ADS Via Regini.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| CMSTP Execution Process Creation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Ping/Del Command Combination | 0.0 | unmeasured | 0 | 0 | 2032 |
| Base64 Encoded PowerShell Command Detected | 0.00014289797084881395 | unmeasured | 0 | 0 | 2032 |
| Sensitive File Access Via Volume Shadow Copy Backup | 0.00017147756501857672 | unmeasured | 0 | 0 | 2032 |
| Suspicious IIS Module Registration | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Base64 Encoded Invoke Keyword | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious Child Process Of Regsvr32 | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - Empire PowerShell UAC Bypass | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Execution From Outlook Temporary Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| Wab/Wabmig Unusual Parent Or Child Processes | 0.0 | unmeasured | 0 | 0 | 2032 |
| Remote Access Tool - Anydesk Execution From Suspicious Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious TSCON Start as SYSTEM | 0.0 | unmeasured | 0 | 0 | 2032 |
| ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - GMER Rootkit Detector and Remover Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| File Download From IP Based URL Via CertOC.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - CrackMapExec Execution Patterns | 0.00017147756501857672 | unmeasured | 0 | 0 | 2032 |
| Suspicious PowerShell Download and Execute Pattern | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Uninstall of Windows Defender Feature via PowerShell | 0.0 | unmeasured | 0 | 0 | 2032 |
| CreateDump Process Dump | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process Of Veeam Dabatase | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Remote Child Process From Outlook | 0.0 | unmeasured | 0 | 0 | 2032 |
| Bypass UAC via WSReset.exe | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Double Extension File Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Enable LM Hash Storage - ProcCreation | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using PkgMgr and DISM | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potential Defense Evasion Via Right-to-Left Override | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious PowerShell Mailbox Export to Share | 0.0 | unmeasured | 0 | 0 | 2032 |
| Windows Defender Definition Files Removed | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious DLL Registered Via Odbcconf.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Schtasks Execution AppData Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| Set Suspicious Files as System Files Using Attrib.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Arbitrary File Download Via IMEWDBLD.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential NTLM Coercion Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HKTL - SharpSuccessor Privilege Escalation Tool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Arbitrary File Download Using Office Application | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious New Service Creation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Service Path Modification | 0.0 | unmeasured | 0 | 0 | 2032 |
| Script Event Consumer Spawning Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| HTML Help HH.EXE Suspicious Child Process | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| PUA - CsExec Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Uncommon FileSystem Load Attempt By Format.com | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious ArcSOC.exe Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Download from Office Domain | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious PowerShell Encoded Command Patterns | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Regedit as Trusted Installer | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process Of Manage Engine ServiceDesk | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Rubeus Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass via ICMLuaUtil | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious Chromium Browser Instance Executed With Custom Extension | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Debugger Registration Cmdline | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Redirection to Local Admin Share | 0.00017147756501857672 | unmeasured | 0 | 0 | 2032 |
| Potential Data Exfiltration Activity Via CommandLine Tools | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential File Overwrite Via Sysinternals SDelete | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed BrowserCore.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Privilege Escalation via Named Pipe Impersonation | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - Quarks PwDump Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential PowerShell Obfuscation Via WCHAR/CHAR | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Execution From Internet Hosted WebDav Share | 0.0 | unmeasured | 0 | 0 | 2032 |
| Dumping of Sensitive Hives Via Reg.EXE | 0.00020005715918833952 | unmeasured | 0 | 0 | 2032 |
| Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Cloudflared.EXE Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Terminal Service Process Spawn | 0.0 | unmeasured | 0 | 0 | 2032 |
| Hacktool - EDR-Freeze Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| TrustedPath UAC Bypass Pattern | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Uninstall Crowdstrike Falcon Sensor | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Office Binary Execution | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Reg Add Suspicious Paths | 0.00011431837667905116 | unmeasured | 0 | 0 | 2032 |
| Microsoft IIS Connection Strings Decryption | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - CreateMiniDump Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Time Travel Debugging Utility Usage | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Rundll32 Invoking Inline VBScript | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Spool Service Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Deletion of Volume Shadow Copies via WMI with PowerShell | 0.0 | unmeasured | 0 | 0 | 2032 |
| Disable Windows IIS HTTP Logging | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Download From Direct IP Via Bitsadmin | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Calculator Usage | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Potential Rundll32 Execution With DLL Stored In ADS | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Plink Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential WinAPI Calls Via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Process Masquerading As SvcHost.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Phishing Pattern ISO in Archive | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Outlook Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious WebDav Client Execution Via Rundll32.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Credential Dumping Via WER | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed AdFind Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Renamed Visual Studio Code Tunnel Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Service Registry Key Deleted Via Reg.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Wsudo Suspicious Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Schtasks Schedule Types | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - LocalPotato Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Suspicious Modification Of Scheduled Tasks | 0.0 | unmeasured | 0 | 0 | 2032 |
| User Added To Highly Privileged Group | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Nimgrab Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| NtdllPipe Like Activity Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| RunMRU Registry Key Deletion | 0.0 | unmeasured | 0 | 0 | 2032 |
| Registry Export of Third-Party Credentials | 0.0 | unmeasured | 0 | 0 | 2032 |
| Invoke-Obfuscation CLIP+ Launcher | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Shells Spawn by Java Utility Keytool | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential AMSI Bypass Via .NET Reflection | 0.0 | unmeasured | 0 | 0 | 2032 |
| Rundll32 Execution Without CommandLine Parameters | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| PUA - Kernel Driver Utility (KDU) Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Hydra Password Bruteforce Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential CommandLine Path Traversal Via Cmd.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - EDRSilencer Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Desktopimgdownldr Command | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious Execution From Parent Process In Public Folder | 0.00014289797084881395 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using NTFS Reparse Point - Process | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| VMToolsd Suspicious Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Persistence Via Logon Scripts - CommandLine | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Renamed NirCmd.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Mpclient.DLL Sideloading Via Defender Binaries | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential PowerShell Execution Policy Tampering - ProcCreation | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpChisel Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Powershell ReverseShell Connection | 0.0 | unmeasured | 0 | 0 | 2032 |
| Python One-Liners with Base64 Decoding | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Curl.EXE Download | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - CrackMapExec Process Patterns | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Mavinject.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious Binary In User Directory Spawned From Office Application | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - PPID Spoofing SelectMyParent Tool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpImpersonation Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Winrs Local Command Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Fast Reverse Proxy (FRP) Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious HH.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| RDP Port Forwarding Rule Added Via Netsh.EXE | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| MpiExec Lolbin | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SOAPHound Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Findstr GPP Passwords | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Obfuscated PowerShell Code | 0.0 | unmeasured | 0 | 0 | 2032 |
| MMC Spawning Windows Shell | 0.00014289797084881395 | unmeasured | 0 | 0 | 2032 |
| DNS Exfiltration and Tunneling Tools Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Conhost.exe CommandLine Path Traversal | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Mimikatz Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Uncommon One Time Only Scheduled Task At 00:00 | 0.0 | unmeasured | 0 | 0 | 2032 |
| Schtasks Creation Or Modification With SYSTEM Privileges | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Dumpert Process Dumper Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using IDiagnostic Profile | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Defense Evasion Via Rename Of Highly Relevant Binaries | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Tampering With RDP Related Registry Keys Via Reg.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Scheduled Task Executing Encoded Payload from Registry | 0.0 | unmeasured | 0 | 0 | 2032 |
| Process Memory Dump Via Comsvcs.DLL | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - Htran/NATBypass Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - UACMe Akagi Execution | 0.0006573306659045442 | unmeasured | 0 | 0 | 0 |
| HackTool - NetExec Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell SAM Copy | 0.0 | unmeasured | 0 | 0 | 2032 |
| Bad Opsec Defaults Sacrificial Processes With Improper Arguments | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious NTLM Authentication on the Printer Spooler Service | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Process Execution From Fake Recycle.Bin Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| RunDLL32 Spawning Explorer | 0.0 | unmeasured | 0 | 0 | 2032 |
| Process Access via TrolleyExpress Exclusion | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Mstsc.EXE Execution With Local RDP File | 0.0 | unmeasured | 0 | 0 | 2032 |
| Windows AMSI Related Registry Tampering Via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential SSH Tunnel Persistence Install Using A Scheduled Task | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Memory Dump Mount Via MemProcFS | 0.0 | unmeasured | 0 | 0 | 2032 |
| PsExec/PAExec Escalation to LOCAL SYSTEM | 0.0 | unmeasured | 0 | 0 | 2032 |
| Net WebClient Casing Anomalies | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential PowerShell Command Line Obfuscation | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Uncommon Userinit Child Process | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Security Privileges Enumeration Via Whoami.EXE | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Fsutil Suspicious Invocation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Process Created Via Wmic.EXE | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Renamed PAExec Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Windows Defender AV Bypass Via Dump64.EXE Rename | 0.0 | unmeasured | 0 | 0 | 2032 |
| Add SafeBoot Keys Via Reg Utility | 0.0 | unmeasured | 0 | 0 | 2032 |
| LOL-Binary Copied From System Directory | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass WSReset | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potential Signing Bypass Via Windows Developer Features | 0.0 | unmeasured | 0 | 0 | 2032 |
| New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Kernel Dump Using Dtrace | 0.0 | unmeasured | 0 | 0 | 2032 |
| SQLite Chromium Profile Data DB Access | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - WinPwn Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Execute Pcwrun.EXE To Leverage Follina | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Base64 Encoded IEX Cmdlet | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - KrbRelay Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Control Panel DLL Load | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - NPS Tunneling Tool Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| HackTool - DInjector PowerShell Cradle Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Windows EventLog Autologger Session Registry Modification Via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Rundll32 Activity Invoking Sys File | 0.0 | unmeasured | 0 | 0 | 2032 |
| Devcon Execution Disabling VMware VMCI Device | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Crassus Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Rundll32 UNC Path Execution | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Bloodhound/Sharphound Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Network Reconnaissance Activity | 0.0 | unmeasured | 0 | 0 | 2032 |
| Outlook EnableUnsafeClientMailRules Setting Enabled | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Gpg.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpView Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Privilege Escalation Using Symlink Between Osk and Cmd | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpDPAPI Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Process Execution From A Potentially Suspicious Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Process Patterns NTDS.DIT Exfil | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| PUA - Netcat Suspicious Execution | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Renamed CreateDump Utility Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed ZOHO Dctask64 Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Python Function Execution Security Warning Disabled In Excel | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Service Binary Directory | 0.0 | unmeasured | 0 | 0 | 2032 |
| Security Service Disabled Via Reg.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Rar Usage with Password and Compression Level | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Processes Spawned by WinRM | 0.0 | unmeasured | 0 | 0 | 2032 |
| Non-privileged Usage of Reg or Powershell | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious MSHTA Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Privilege Escalation To LOCAL SYSTEM | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Regsvr32 Execution From Remote Share | 0.0 | unmeasured | 0 | 0 | 2032 |
| Mavinject Inject DLL Into Running Process | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Windows Shell/Scripting Processes Spawning Suspicious Programs | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| Copying Sensitive Files with Credential Data | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Delete All Scheduled Tasks | 0.0 | unmeasured | 0 | 0 | 2032 |
| Security Event Logging Disabled via MiniNt Registry Key - Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpUp PrivEsc Tool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| MSHTA Execution with Suspicious File Extensions | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| HackTool - SharpEvtMute Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Recon Activity Using DriverQuery.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - PingCastle Execution From Potentially Suspicious Parent | 0.0 | unmeasured | 0 | 0 | 2032 |
| System File Execution Location Anomaly | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed PsExec Service Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential SysInternals ProcDump Evasion | 0.0 | unmeasured | 0 | 0 | 2032 |
| Sticky Key Like Backdoor Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Run PowerShell Script from ADS | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Splwow64 Without Params | 0.0 | unmeasured | 0 | 0 | 2032 |
| Forfiles.EXE Child Process Masquerading | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Whoami Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Tor Client/Browser Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using Windows Media Player - Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Sysmon Driver Unloaded Via Fltmc.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Windows Update Agent Empty Cmdline | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed SysInternals DebugView Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| New ActiveScriptEventConsumer Created Via Wmic.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious MSDT Parent Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Microsoft OneNote Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| File Download And Execution Via IEExec.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Hashcat Password Cracker Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious WMIC Execution Via Office Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Microsoft IIS Service Account Password Dumped | 0.0005144326950557302 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Using DismHost | 0.0 | unmeasured | 0 | 0 | 2032 |
| Proxy Execution Via Wuauclt.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed NetSupport RAT Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - RunXCmd Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Certipy Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious GoogleUpdate Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| Python Spawning Pretty TTY on Windows | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Sliver C2 Implant Activity Pattern | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Provlaunch.EXE Child Process | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - Stracciatella Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| UAC Bypass Tools Using ComputerDefaults | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Schtasks Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Child Process Of Wermgr.EXE | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potential Manage-bde.wsf Abuse To Proxy Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Usage Of ShellExec_RunDLL | 0.0 | unmeasured | 0 | 0 | 2032 |
| Disabling Windows Defender WMI Autologger Session via Reg.exe | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - HandleKatz LSASS Dumper Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Suspicious File Download From IP Via Wget.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Chromium Browser Headless Execution To Mockbin Like Site | 0.0 | unmeasured | 0 | 0 | 2032 |
| Use of W32tm as Timer | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Process Injection Via Msra.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential PowerShell Obfuscation Via Reversed Commands | 0.0 | unmeasured | 0 | 0 | 2032 |
| Rundll32 Registered COM Objects | 0.0 | unmeasured | 0 | 0 | 2032 |
| Bypass UAC via Fodhelper.exe | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Explorer NOUACCHECK Flag | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential LSASS Process Dump Via Procdump | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Powershell Base64 Encoded MpPreference Cmdlet | 0.0 | unmeasured | 0 | 0 | 2032 |
| Operator Bloopers Cobalt Strike Modules | 0.0 | unmeasured | 0 | 0 | 2032 |
| Run PowerShell Script from Redirected Input Stream | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - WSASS Execution | 0.0 | unmeasured | 0 | 0 | 0 |
| Abused Debug Privilege by Arbitrary Parent Processes | 0.0003143755358673907 | unmeasured | 0 | 0 | 2032 |
| Webshell Detection With Command Line Keywords | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious File Download From IP Via Wget.EXE - Paths | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - SecurityXploded Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Uncommon Child Process Of Setres.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| LSASS Dump Keyword In CommandLine | 8.573878250928836e-05 | unmeasured | 0 | 0 | 2032 |
| Raccine Uninstall | 0.0 | unmeasured | 0 | 0 | 2032 |
| CMSTP UAC Bypass via COM Object Access | 0.00014289797084881395 | unmeasured | 0 | 0 | 2032 |
| SafeBoot Registry Key Deleted Via Reg.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - AdvancedRun Suspicious Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - CleanWipe Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious Event Viewer Child Process | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Uncommon Svchost Command Line Parameter | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious Office Document Executed From Trusted Location | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - CrackMapExec Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potentially Suspicious Call To Win32_NTEventlogFile Class | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Eventlog Clearing or Configuration Change Activity | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Msdt.EXE Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential Crypto Mining Activity | 0.0 | unmeasured | 0 | 0 | 2032 |
| VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| Execution of Powershell Script in Public Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Set-Acl On Windows Folder | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Active Directory Database Snapshot Via ADExplorer | 0.0 | unmeasured | 0 | 0 | 2032 |
| Possible Privilege Escalation via Weak Service Permissions | 0.0 | unmeasured | 0 | 0 | 2032 |
| UEFI Persistence Via Wpbbin - ProcessCreation | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious GrpConv Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Potential PowerShell Execution Via DLL | 0.0 | unmeasured | 0 | 0 | 2032 |
| Invoke-Obfuscation STDIN+ Launcher | 0.0 | unmeasured | 0 | 0 | 2032 |
| Vulnerable Driver Blocklist Registry Tampering Via CommandLine | 0.0 | unmeasured | 0 | 0 | 2032 |
| Execution via WorkFolders.exe | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Rundll32 Execution With Image Extension | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious Process By Web Server Process | 5.715918833952558e-05 | unmeasured | 0 | 0 | 2032 |
| Kernel Memory Dump Via LiveKD | 0.0 | unmeasured | 0 | 0 | 2032 |
| PowerShell Get-Process LSASS | 0.0 | unmeasured | 0 | 0 | 2032 |
| Renamed Vmnat.exe Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious GUP Usage | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call | 0.0 | unmeasured | 0 | 0 | 2032 |
| HackTool - HollowReaper Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| Webshell Hacking Activity Patterns | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| Suspicious PowerShell Parameter Substring | 0.0 | unmeasured | 0 | 0 | 2032 |
| File In Suspicious Location Encoded To Base64 Via Certutil.EXE | 0.0 | unmeasured | 0 | 0 | 2032 |
| New User Created Via Net.EXE With Never Expire Option | 0.0 | unmeasured | 0 | 0 | 2032 |
| Suspicious Process Parents | 0.0002572163475278651 | unmeasured | 0 | 0 | 2032 |
| PsExec Service Child Process Execution as LOCAL SYSTEM | 2.857959416976279e-05 | unmeasured | 0 | 0 | 2032 |
| PUA - Restic Backup Tool Execution | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - NirCmd Execution As LOCAL SYSTEM | 0.0 | unmeasured | 0 | 0 | 2032 |
| PUA - Rclone Execution | 0.0 | unmeasured | 0 | 0 | 2032 |

## FP-tuning candidates (over-broad on real traffic)
- none above threshold
---

## Run provenance (first real end-to-end run)

**Engine:** vendored Zircolite 3.7.6. The SAME compiled ruleset
(`Zircolite/rules/rules_windows_sysmon.json`, 2680 rules) was used for BOTH the
recall and the precision pass, so both metrics come from the identical engine.
Only the 609 loaded high+critical, stateless SigmaHQ `process_creation` rules are
SCORED (608/609 of those titles exist in the compiled ruleset; 1 — *NTLM Hash
Leak Via Curl NTLM Authentication* — is newer than the vendored ruleset and was
therefore never evaluated by the engine).

**Precision side — COMISET Real-Environment benign sample**
(`data/comiset/real_benign_sample.jsonl`, gitignored):
streamed from `~/comiset-dl/Comiset23_Real_Environment_Dataset.zip` (934 GB
uncompressed JSONL) via `unzip -p | scripts/build_benign_sample.py`, filtered to
Sysmon `Microsoft-Windows-Sysmon/Operational` EID-1 (process creation). EID-1 is
very sparse in the early file region (~28 / 1M lines) and arrives in dense bursts
deeper in. Capture was stopped after a dense burst (decompression is I/O-bound
and sequential).

- EID-1 events captured: **2032**
- label split (per-event `_source.rule_technique_id` present = malicious):
  **1870 benign / 162 malicious**
- per-event labels injected under `_source` as `sigmaforge_eid` (sha1 of the raw
  line) + `sigmaforge_label`, surfaced verbatim by the identity mappings in
  `data/mappings/comiset.yaml`.

**Recall side — native EVTX attack corpus**
(`~/sigmaforge-v0/EVTX-ATTACK-SAMPLES`, all-malicious): Zircolite run directly on
the 278 `.evtx` files with the default Zircolite `fieldMappings.yaml`.

- total attack-corpus events parsed (recall denominator `n_attack_events`):
  **34990**
- caveat: only **~1499** of those 34990 are process-creation events
  (Sysmon EID-1 or Security 4688); the rest are other channels the
  `process_creation` rules can never match. Recall is reported against the full
  34990 (as specified), so the absolute fractions are small **by construction** —
  read them as relative recall across rules, not as detection probability.
- 332 rules fired on the attack corpus (1083 unique (rule, EventRecordID) pairs);
  **101 of the 609 loaded rules** scored at least one attack TP.

**Positive control:** PASSED — multiple malicious-labelled benign-corpus events
fired (e.g. the bcdedit rule, all 34 hits labelled malicious), so the COMISET
field mapping is live and precision is trustable.

## Headline

| rule | recall (tp/34990) | precision@COMISET | tp | fp |
|---|---|---|---|---|
| Boot Configuration Tampering Via Bcdedit.EXE | 0.0000572 (2) | **1.0** | 34 | 0 |
| Suspicious SYSTEM User Process Creation | 0.000714 (25) | unmeasured | 0 | 0 |
| HackTool - UACMe Akagi Execution | 0.000657 (23) | unmeasured | 0 | 0 |
| Microsoft IIS Service Account Password Dumped | 0.000514 (18) | unmeasured | 0 | 0 |
| Whoami.EXE Execution From Privileged Process | 0.000314 (11) | unmeasured | 0 | 0 |

Exactly **one** loaded rule produced a measurable precision@COMISET on this run:
*Boot Configuration Tampering Via Bcdedit.EXE* — 34 unique benign-corpus hits,
**all 34 labelled malicious (T1490)** → precision 1.0, **0 false positives**.

**608 of 609 loaded rules are "unmeasured" for precision**, for two distinct
(honest) reasons:
1. **Did not fire on the benign corpus** (the large majority). Precision is
   undefined for a rule with `tp+fp = 0` — there is nothing to divide. 100 of
   these still have a measured *recall* on the attack corpus.
2. **Zero field coverage** (19 rules): their selection fields (e.g. the combined
   `Hashes` field, certain `User`/`Provider` forms) are not carried by the
   COMISET winlogbeat pipeline, so the rule never effectively ran on any event.

No rule fired ≥5 times on benign traffic → **0 FP-tuning candidates** this run.

## A12 — recommended min-events-per-rule precision floor

Coverage over this real sample is **binary**, not graded: 590/609 rules cover
**all 2032** events (they key on `CommandLine`/`Image`, present in every EID-1
event) and 19/609 cover **0** (field absent from the dataset). There is no middle
band for `process_creation` rules. The floor therefore functions as a
**sample-size gate**, not a per-rule discriminator.

**Recommendation:** `floor = max(200, 0.10 × benign_sample_size)`.
- For this 2032-event sample that is **203**; the run used 1000, which all 590
  covered rules also clear, so the headline is unaffected.
- The 10% term scales the floor with the sample so a rule must be exercised on a
  non-trivial slice before its precision is trusted; the absolute floor of 200
  stops a tiny sample from self-certifying.
- The real lever for measuring MORE rules is **sample size + diversity**, not a
  lower floor: 608 rules are unmeasured because they never fired on 2032 benign
  events, not because they were floor-gated.
