# Finding: "Suspicious Windows Service Tampering" — over-broad on installer activity

**Rule:** `Suspicious Windows Service Tampering`
(`sigma/rules/windows/process_creation/proc_creation_win_susp_service_tamper.yml`,
id `ce72ef99-22f1-43d4-8695-419dcb5d9330`, level `high`, SigmaHQ / Nextron).

**Status: DONE_WITH_CONCERNS** — the over-broad FP pattern is real and verified
per-event; the fix takes benign FP 66 → 0. The concern is on the attack side:
the rule already catches **0** of this attack corpus's service-tamper samples
(corpus limitation, not a regression), so "TP intact" can only be demonstrated
as **0 → 0**, not as a non-zero TP held constant.

---

## The story in one paragraph

The rule is meant to catch ransomware/operators stopping or deleting security,
backup and database services (`net stop`, `sc delete`, `Stop-Service`, …) by
name. On this benign corpus it fires **66 times** — and every single one of
those 66 is the **Ninite** software installer running `net stop "TeamViewer N"`
as a routine pre-install/upgrade step. `TeamViewer` is in the rule's hard-coded
service-name list, ` stop ` is one of its verbs, and the launching binary is the
signed Microsoft `net.exe` — so all three of the rule's selections line up on
ordinary installer activity. A one-line parent-process filter excluding the
Ninite installer lineage removes all 66 with no effect on attack detection.

---

## 1. The hits (real count: 66)

Single-rule run (1-rule Zircolite ruleset extracted by id from
`Zircolite/rules/rules_windows_sysmon.json`, so there is no title-match
ambiguity; SQL is byte-for-byte the compiled SigmaHQ rule):

```
uv run python Zircolite/zircolite.py \
  --events data/comiset/combined_benign_sample.jsonl --json-input \
  --ruleset reports/needle/rule_service_tamper_orig.json \
  --config data/mappings/comiset.yaml --outfile <out>
→ 66 HIGH detections across 17,124 events
```

Breakdown of all 66 matched events:

| dimension | value | count |
|---|---|---|
| `Image` / `OriginalFileName` | `net.exe` | 33 |
| `Image` / `OriginalFileName` | `net1.exe` (the relaunch `net.exe` always spawns) | 33 |
| matched verb | ` stop ` | 66 / 66 |
| matched service token | `TeamViewer` | 66 / 66 |
| `Company` of the tool | `Microsoft Corporation` (signed `net.exe`) | 66 / 66 |
| `sigmaforge_label` | `benign` | **66 / 66** |
| parent of the `net.exe` leg | `…\Temp\<guid>\Ninite.exe` | 33 |
| parent of the `net1.exe` leg | `…\net.exe` running the same `net stop "TeamViewer N"` | 33 |

Distinct command lines: `net stop "TeamViewer 5"` … `net stop "TeamViewer 15"`
(11 versions) × {net.exe leg, net1.exe leg} × 3 host snapshots = 66.

Hosts / users (three benign workstation snapshots, ordinary user accounts):
`DESKTOP-6D0DBMB\testme`, `WINDEV2310EVAL\User`, `Agamemnon\neo`.

### Redacted exemplars

**net.exe leg** (the installer directly calling net):
```
Image            : C:\Windows\SysWOW64\net.exe        (Microsoft Corporation, OriginalFileName net.exe)
CommandLine      : net stop "TeamViewer 5"
ParentImage      : C:\Users\<user>\AppData\Local\Temp\<guid>\Ninite.exe
ParentCommandLine: "...\Ninite.exe" "<hash>" /fullpath "C:\...\Ninite 7Zip Audacity Chrome Dropbox Eclipse Installer.exe" /relaunch
User             : <host>\<user>
sigmaforge_label : benign
```

**net1.exe leg** (the relaunch net.exe spawns for itself — same TeamViewer stop):
```
Image            : C:\Windows\SysWOW64\net1.exe
CommandLine      : C:\Windows\system32\net1 stop "TeamViewer 5"
ParentImage      : C:\Windows\SysWOW64\net.exe
ParentCommandLine: net stop "TeamViewer 5"
User             : <host>\<user>
sigmaforge_label : benign
```

## 2. Per-event verdict: real-FP vs mislabel vs ambiguous

I read all 66 (grouped by the 22 distinct command lines + parent context):

| verdict | count | reasoning |
|---|---|---|
| **real false positive** | **66** | Signed Microsoft `net.exe`, launched by the Ninite installer (or its own `net1.exe` relaunch), stopping the TeamViewer service so the install/upgrade can proceed. Benign-labelled and benign-by-inspection. |
| mislabel (event is actually attacker-ish but tagged benign) | 0 | — |
| ambiguous | 0 | — |

**Honesty core: there are no mislabels here.** All 66 carry
`sigmaforge_label=benign`, and the per-event reading agrees with that label —
this is genuinely benign installer activity, not noisy-label slop. So the
finding does **not** weaken on the label-quality axis: it is a true over-broad
rule on this corpus. (The corpus caveat below is separate and is about
representativeness, not mislabelling.)

## 3. Root cause

`condition: all of selection_*` → an event fires only if it matches **all three**:

1. `selection_tools_img` — a service-control binary
   (here `OriginalFileName: net.exe` / `net1.exe`). ✔ Ninite uses signed `net.exe`.
2. `selection_tools_cli` — a tamper verb. The matched value is **` stop `**
   (`CommandLine|contains: ' stop '`). ✔ `net stop "TeamViewer N"`.
3. `selection_services` — a known service name. The matched value is
   **`TeamViewer`** (line 248 of the rule). ✔ `"TeamViewer N"` contains it.

The over-broad combination is **`selection_tools_cli: ' stop '` × the
broad-product entries in `selection_services` (here `TeamViewer`)**. `TeamViewer`
is a remote-admin product, not an EDR/AV — stopping it is exactly what an
installer/upgrader does, so it generates the same `net stop <service>` signature
as the ransomware behaviour the rule targets. The rule has no parent-process or
"not an installer" constraint, so legitimate Ninite installs trip it. (The
rule's own `falsepositives:` note literally anticipates this: *"Administrators or
tools shutting down the services due to upgrade… consider adding filters to the
parent process."*)

## 4. Fix (one-line `filter:`)

Exclude the Ninite installer lineage. Because `net.exe` always relaunches itself
as `net1.exe`, the filter has to cover both legs (the installer is the parent of
the `net.exe` leg, and `net.exe` running the TeamViewer stop is the parent of the
`net1.exe` leg).

### Sigma diff (before → after)

```diff
 detection:
     selection_tools_img:
         ...
     selection_tools_cli:
         ...
     selection_services:
         ...
-    condition: all of selection_*
+    filter_main_installer:
+        # benign software installer (Ninite) stopping a service to upgrade it;
+        # covers both the net.exe leg (parent = Ninite) and the net1.exe relaunch
+        - ParentImage|endswith: '\Ninite.exe'
+        - ParentImage|endswith: '\net.exe'
+          ParentCommandLine|contains: 'net stop "TeamViewer'
+    condition: all of selection_* and not 1 of filter_main_*
```

(Compiled equivalent applied to the SQL rule for retest —
`reports/needle/rule_service_tamper_patched.json`:)

```sql
... AND NOT ( (ParentImage LIKE '%\Ninite.exe' ESCAPE '\')
   OR (ParentImage LIKE '%\net.exe' ESCAPE '\'
       AND ParentCommandLine LIKE '%net stop "TeamViewer%' ESCAPE '\') )
```

## 5. Retest — the four numbers

| metric | original rule | patched rule |
|---|---|---|
| **benign-corpus FP** | **66** | **0** |
| **attack-EVTX TP** | **0** | **0** |

- benign FP **66 → 0** (commands + outputs in `reports/needle/`).
- attack TP **0 → 0** — the filter is parent-anchored on a binary
  (`Ninite.exe`) and a parent-command pattern that **do not occur anywhere in
  the attack corpus** (verified: 0 attack events reference `Ninite`), so it
  provably cannot suppress an attack match.

### Why the original attack TP is already 0 (important caveat)

`~/sigmaforge-v0/EVTX-ATTACK-SAMPLES/` contains exactly **3** events that match
the rule's tool+verb selections:

```
sc.exe  stop AtomicTestService
sc.exe  delete AtomicTestService
sc  stop CDPSvc
```

None of these fire the rule, because their service names
(`AtomicTestService`, `CDPSvc`) are **not in the rule's hard-coded
`selection_services` list** — so the third selection fails and the original rule
matches 0 attack events. The fix therefore cannot *drop* a TP it never had. This
is a property of this attack corpus (it has no in-list service being tampered),
not of the patch.

## Caveats (read before quoting these numbers)

1. **Benign corpus is ~88% Nextron goodware**, not real SOC noise (see
   `reports/run2.md`). 66/17,124 here is a **tuning candidate on this corpus**,
   not a measured production FP rate. That said, Ninite-stops-TeamViewer-to-
   upgrade is a real-world benign pattern, so the FP is plausible beyond this
   corpus.
2. **0 of the 66 were mislabels.** All 66 are benign-labelled and benign on
   inspection — the finding is a genuine over-broad rule, it does not weaken on
   label quality.
3. **TP is "0 → 0", not "N → N".** I cannot show the patched rule still catches a
   live attack from this corpus, because the original rule already catches none
   of it (the corpus has no in-list service being tampered). The filter is
   designed to be attack-safe by construction (Ninite lineage absent from the
   attack set), but a corpus with an in-list service-tamper sample would be
   needed to demonstrate non-zero TP retention.
4. **Filter scope.** The fix is deliberately narrow (Ninite + the net1 relaunch
   of a TeamViewer stop). It does not address the more general weakness that
   `selection_services` lists broad remote-admin/DB products (`TeamViewer`,
   `MySQL`, `Tomcat`, …) whose legitimate stop/restart by other installers or
   admins would also fire the rule. A broader fix (drop non-security products
   from the list, or require a suspicious parent) is a separate change.

---

## Reproduce

Artifacts in `reports/needle/`:
`rule_service_tamper_orig.json`, `rule_service_tamper_patched.json`,
`benign_orig_detections.json` (66), `benign_patched_detections.json` (0),
`attack_orig_detections.json` (0), `attack_patched_detections.json` (0),
`attack.db` (flat attack event DB used to enumerate the 3 tamper events).
