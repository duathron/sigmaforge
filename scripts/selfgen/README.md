# Self-generated benign corpus (Windows VM kit)

Targeted benign diversity for the precision/false-positive side of the backtest.
Nextron's `evtx-baseline` is ~88% goodware *installers*; this kit produces the
*behavioural* noise that actually makes high/critical Sigma rules false-positive:
admin PowerShell, scheduled tasks, LOLBins, service mgmt, WMI, discovery,
browser/Office launches.

Every event captured is **benign by construction** — `normal_workday.ps1` runs no
attacks. Some actions deliberately *resemble* attacker tradecraft (certutil
download, schtasks, encoded PowerShell) because that resemblance is exactly what a
false-positive test needs to measure.

> **Authorized lab use only.** Run on your own throwaway Windows VM. Snapshot
> before, revert after. This is defensive detection-engineering, not attack.

## Why a VM (and why you, not the agent)

Sysmon EID-1 is Windows-only telemetry; it cannot be produced on the Mac. So this
one step is yours: stand up a Win10/11 VM, run the script, export the `.evtx`, hand
it back. Everything after that (ingest, scoring, report) is automated on the repo
side.

## Steps

### 1. VM + Sysmon
- Win10/11 VM (UTM/Parallels/VirtualBox). Take a clean snapshot.
- Install Sysmon with the **olafhartong/sysmon-modular** config (MIT — license-safe
  to redistribute, unlike SwiftOnSecurity's config which has *no license file*):
  ```powershell
  # from an elevated PowerShell, in a folder where you cloned/downloaded the config
  # https://github.com/olafhartong/sysmon-modular  (sysmonconfig.xml)
  .\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
  ```
  EID-1 logs Image / CommandLine / ParentImage / OriginalFileName by default
  (the fields the loaded rules inspect). OriginalFileName needs Sysmon >= 10 (any
  current build).

### 2. Generate the activity
From an **elevated** PowerShell:
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\normal_workday.ps1 -Sessions 5
```
`-Sessions N` reruns the activity block N times with jitter for volume/variety.

### 3. Export the Sysmon log to EVTX
```powershell
mkdir C:\sf_out
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\sf_out\selfgen_benign.evtx
```
Copy `C:\sf_out\selfgen_benign.evtx` off the VM (shared folder / scp).

### 4. Ingest on the repo side (reuses the Nextron path — no new code)
Self-gen EVTX is native Sysmon EID-1, identical in shape to Nextron's, so
`build_nextron_benign.py` ingests it unchanged. Put the `.evtx` in a folder and:
```bash
# append the self-gen benign events onto the existing combined corpus
uv run python scripts/build_nextron_benign.py \
    --evtx-root ~/sigmaforge-v0/selfgen \
    --append data/comiset/combined_benign_sample.jsonl \
    --out    data/comiset/combined_benign_sample.jsonl
```
Then re-run the backtest (`scripts/run4_backtest.py`). The new benign events do two
distinct things (these are *separate* counters in the code):
- they raise `events_evaluated` — the coverage-floor counter, which counts **all**
  corpus events (benign- and malicious-labelled) carrying a rule's selection fields.
  This is the gate `precision_or_unmeasured` checks against the 1000-event floor, so
  more rules clear the floor and become precision-*measurable*.
- they raise `benign_events_evaluated` (benign-labelled only) — which moves rules out
  of the `no-benign-exemplars` bucket, where precision computes to a tautological 1.0
  with no real FP signal, into a **genuine** FP measurement.

## Opt-in (snapshot-revert VM only)
Omitted from the script because they change state in ways not cleanly reversible,
but valuable FP samples if you can revert the snapshot afterwards:
- `regsvr32` registering a real COM DLL (`/s`), then unregister (`/u`).
- `mshta` running a local benign `.hta`.
- Office macros enabled + a benign macro that spawns a child process (the classic
  Office-spawns-LOLBin FP).
Add these as extra `Step` blocks and re-export.

## What this unlocks
More benign exemplars carrying the selection fields raise both counters above:
more rules clear the coverage floor (precision-*measurable*), and more rules leave
the `no-benign-exemplars` tautology bucket for a real FP signal. The point isn't
more firings; a rule that *doesn't* fire on this realistic noise earns an honest
low-FP signal instead of `unmeasured` / `no benign exemplars`. (How many rules are
FP-measurable vs no-benign-exemplars today is recorded in the latest
`reports/run4.md` and its manifest — cite that run, don't guess a figure.)
