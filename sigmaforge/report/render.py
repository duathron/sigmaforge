def render_report(
    rows: list[dict],
    funnel: dict,
    source: str = "COMISET",
    min_events: int = 1000,
    fp_tuning_threshold: int = 5,
    run_hash: str | None = None,
    corpus_note: str | None = None,
    recall_note: str | None = None,
) -> str:
    """A10/A8: the deliverable. A human-readable FP-tuning report.
    Leads with the corpus-scope + noisy-label caveat; precision labelled precision@SOURCE.
    `corpus_note` MUST disclose the benign corpus composition when it is blended (A8 honesty).
    `recall_note` (FIX B) discloses how recall is measured (per-technique vs pooled)."""
    lines = [
        f"# Sigmaforge backtest report ({source})",
        "",
        *([f"_run hash (worker-invariant): `{run_hash}`_", ""] if run_hash else []),
        f"> Precision is **precision@{source}**, measured on the benign corpus described below "
        f"— not a general/cross-environment false-positive rate. "
        f"Labels are NOISY ground truth (rule-pattern attributions, e.g. OneDrive.exe tagged "
        f"as an ATT&CK technique), so a measured FP may be a mislabel. Recall is measured on "
        f"the labeled native-EVTX attack corpora over PROCESS-CREATION events only (the loaded "
        f"ruleset is 100% process_creation). Precision floor: {min_events} evaluated events.",
        *([f"> **Benign corpus composition:** {corpus_note}"] if corpus_note else []),
        *([f"> **Recall method (FIX B):** {recall_note}"] if recall_note else []),
        "",
        "> **Precision tautology caveat (BLOCKER-2):** a rule showing precision = 1.0 with fp = 0 "
        "is only trustworthy if benign-labelled events actually matched its selection. Rules whose "
        "benign-corpus coverage held **zero benign exemplars** are flagged `no-benign-exemplars` "
        "below: their fp = 0 is true *by construction*, so precision = 1.0 carries **no "
        "false-positive signal** — it is not evidence of FP-resistance.",
        "",
        "## Funnel",
    ]
    for stage in ("candidate", "loaded", "stateless", "fires", "survives_fp"):
        if stage in funnel:
            lines.append(f"- {stage}: {funnel[stage]}")
    lines += [
        "",
        "## Per-rule",
        "",
        "| rule | recall | precision@"
        + source
        + " | tp | fp | events_evaluated | benign_events_evaluated | precision_signal |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        prec = r.get(f"precision@{source}", "unmeasured")
        # precision_signal: does the precision number carry any FP information?
        if prec == "unmeasured":
            signal = "n/a (unmeasured)"
        elif r.get("no_benign_exemplars"):
            signal = "NONE (no-benign-exemplars)"
        else:
            signal = "real"
        lines.append(
            f"| {r.get('rule')} | {r.get('recall')} | {prec} "
            f"| {r.get('tp')} | {r.get('fp')} | {r.get('events_evaluated')} "
            f"| {r.get('benign_events_evaluated', 'n/a')} | {signal} |"
        )
    # FP-tuning section: surface over-broad rules (the analyst-judgment deliverable)
    noisy = [r for r in rows if isinstance(r.get("fp"), int) and r["fp"] >= fp_tuning_threshold]
    lines += ["", "## FP-tuning candidates (over-broad on real traffic)"]
    if noisy:
        for r in sorted(noisy, key=lambda x: -x["fp"]):
            lines.append(
                f"- **{r.get('rule')}** catches the attack but fires {r['fp']}x on benign "
                f"activity — candidate for tightening."
            )
    else:
        lines.append("- none above threshold")

    # BLOCKER-2: rules whose measured precision is tautological (no benign exemplars).
    tautology = [r for r in rows if r.get("no_benign_exemplars") and isinstance(r.get(f"precision@{source}"), float)]
    lines += ["", "## Precision tautologies (no benign exemplars — precision carries no FP signal)"]
    if tautology:
        for r in sorted(tautology, key=lambda x: str(x.get("rule"))):
            lines.append(
                f"- **{r.get('rule')}** reports precision@{source} = {r.get(f'precision@{source}')} "
                f"with fp = {r.get('fp')}, but **0 benign-labelled events matched its selection** — "
                f"fp = 0 is true by construction. No FP-resistance is demonstrated; precision is "
                f"effectively unmeasured for FP purposes."
            )
    else:
        lines.append("- none (every measured rule had at least one benign exemplar)")
    return "\n".join(lines)
