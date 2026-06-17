<#
.SYNOPSIS
  Sigmaforge benign self-generation: a "normal admin workday" on a Windows VM.

.DESCRIPTION
  Runs REAL but HARMLESS Windows admin/user activity while Sysmon records it as
  EID-1 (process creation). The goal is BENIGN DIVERSITY: exercise the command-line
  shapes that high/critical SigmaHQ process_creation rules inspect (admin PowerShell,
  scheduled tasks, LOLBins, service mgmt, WMI, discovery, Office/browser), so the
  backtest can measure how often those rules FALSE-POSITIVE on legitimate activity.

  Every event captured during this run is benign BY CONSTRUCTION: this script runs
  NO attacks. Some actions deliberately resemble attacker tradecraft (certutil
  download, schtasks, rundll32) because that resemblance is the whole point of a
  false-positive test -- but each is a legitimate admin action and is reverted.

  AUTHORIZED USE ONLY: your own throwaway lab VM. Snapshot before, revert after.

.NOTES
  Sysmon config: olafhartong/sysmon-modular (MIT) -- see README.md in this folder.
  Borderline-but-benign actions that change system state in ways not cleanly
  reversible (regsvr32 COM register, mshta) are intentionally OMITTED here and
  listed in README as opt-in for a snapshot-revert VM.
#>

[CmdletBinding()]
param(
    # How many "work sessions" to simulate (each reruns the activity block with jitter).
    [int]$Sessions = 5,
    # Max random pause (seconds) between actions, to spread events over time.
    [int]$MaxJitterSeconds = 4,
    # A scratch dir for downloads / temp files (cleaned at the end).
    [string]$WorkDir = "$env:TEMP\sf_benign"
)

$ErrorActionPreference = 'Continue'   # benign noise: keep going even if one action errors
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

function Step([string]$Name, [scriptblock]$Action) {
    Write-Host "[+] $Name"
    try { & $Action } catch { Write-Host "    (non-fatal: $($_.Exception.Message))" }
    Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum ([math]::Max(1, $MaxJitterSeconds)))
}

for ($s = 1; $s -le $Sessions; $s++) {
    Write-Host "===== session $s / $Sessions ====="

    # --- Admin PowerShell (rules watch -EncodedCommand, -Command, download cradles) ---
    Step "powershell -Command inline" {
        powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5 | Out-Null"
    }
    Step "powershell Invoke-WebRequest (benign admin download)" {
        powershell.exe -NoProfile -Command "Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/' -OutFile '$WorkDir\aka.html'" 2>$null
    }
    Step "powershell base64 -EncodedCommand (benign: writes Host)" {
        # benign payload: [Console]::Out.WriteLine('hi') -- encoded the same way attackers encode,
        # so encoded-command rules get a legitimate sample to (not) fire on.
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("[Console]::Out.WriteLine('hi')"))
        powershell.exe -NoProfile -EncodedCommand $enc
    }

    # --- Scheduled tasks (create / run / delete -- standard admin automation) ---
    Step "schtasks create+run+delete" {
        $tn = "SF_Benign_$s"
        schtasks.exe /Create /TN $tn /TR "cmd.exe /c echo benign" /SC ONCE /ST 23:59 /F | Out-Null
        schtasks.exe /Run /TN $tn | Out-Null
        schtasks.exe /Query /TN $tn | Out-Null
        schtasks.exe /Delete /TN $tn /F | Out-Null
    }

    # --- LOLBins used legitimately (the classic FP source) ---
    Step "certutil download (admin file fetch)" {
        certutil.exe -urlcache -split -f "https://aka.ms/" "$WorkDir\certutil.html" | Out-Null
    }
    Step "bitsadmin transfer (admin file fetch)" {
        bitsadmin.exe /transfer sfbenign /download "https://aka.ms/" "$WorkDir\bits.html" | Out-Null
    }
    Step "rundll32 control panel (legit shell32)" {
        # opens then we don't interact; benign, no persistence
        Start-Process rundll32.exe -ArgumentList 'shell32.dll,Control_RunDLL' -WindowStyle Minimized
        Start-Sleep 1
        Get-Process -Name rundll32 -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
    }

    # --- Service management (admin) ---
    Step "sc.exe query services" {
        sc.exe query | Out-Null
        sc.exe queryex type=service state=all | Out-Null
    }

    # --- WMI (admin inventory) ---
    Step "wmic process/os inventory" {
        wmic.exe process get Name,ProcessId,CommandLine /format:list | Out-Null
        wmic.exe os get Caption,Version /format:list | Out-Null
    }

    # --- Discovery (admin / helpdesk) ---
    Step "discovery: whoami/net/nltest/systeminfo" {
        whoami.exe /all | Out-Null
        net.exe user | Out-Null
        net.exe localgroup administrators | Out-Null
        nltest.exe /dclist: 2>$null | Out-Null   # errors on standalone; cmdline still logged
        systeminfo.exe | Out-Null
        ipconfig.exe /all | Out-Null
        tasklist.exe /v | Out-Null
    }

    # --- Normal user app launches ---
    Step "launch browser + notepad + calc" {
        Start-Process "msedge.exe" "https://example.com" -ErrorAction SilentlyContinue
        Start-Process "notepad.exe"
        Start-Process "calc.exe"
        Start-Sleep 2
        foreach ($p in 'notepad', 'calculatorapp', 'win32calc') {
            Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
        }
    }
}

# --- cleanup scratch dir (events already recorded by Sysmon) ---
Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
Write-Host "===== done. Export the Sysmon log next (see README.md). ====="
