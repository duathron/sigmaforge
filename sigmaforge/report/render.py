def _with_reason(value, reason: str | None):
    """C2: append the reason-code inline when a cell is unmeasured, e.g.
    ``unmeasured (technique-0-events)``. A measured (numeric) value is unchanged."""
    if value == "unmeasured" and reason:
        return f"unmeasured ({reason})"
    return value


def render_report(
    rows: list[dict],
    funnel: dict,
    source: str = "COMISET",
    min_events: int = 1000,
    fp_tuning_threshold: int = 5,
    run_hash: str | None = None,
    corpus_note: str | None = None,
    recall_note: str | None = None,
    caveats: dict | None = None,
) -> str:
    """A10/A8: the deliverable. A human-readable FP-tuning report.
    Leads with the corpus-scope + noisy-label caveat; precision labelled precision@SOURCE.
    `corpus_note` MUST disclose the benign corpus composition when it is blended (A8 honesty).
    `recall_note` (FIX B) discloses how recall is measured (per-technique vs pooled).
    `caveats` (C2) is a DATA dict (floor, recommended_floor, corpus path-form split, ...)
    rendered into a Caveats block — run-specific provenance is passed as data, not as a
    hardcoded prose string lifted from a script header."""
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
        # C2: when a cell is unmeasured, render its reason-code inline (never a bare token)
        recall_cell = _with_reason(r.get("recall"), r.get("recall_reason"))
        prec_cell = _with_reason(prec, r.get("precision_reason"))
        lines.append(
            f"| {r.get('rule')} | {recall_cell} | {prec_cell} "
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

    # C2: data-generated caveats block (floor, recommended floor, corpus path-form split,
    # ...). Generated from the passed dict so the CLI path emits the same honesty discipline
    # run7's script header used to hardcode — run-specific provenance flows as DATA, not prose.
    if caveats:
        lines += ["", "## Caveats"]
        if "floor" in caveats:
            lines.append(f"- Precision floor in effect: **{caveats['floor']}** evaluated events.")
        if "recommended_floor" in caveats:
            lines.append(
                f"- Recommended floor for a stable precision estimate: **{caveats['recommended_floor']}** events."
            )
        if caveats.get("path_form_split"):
            lines.append(f"- Corpus path-form note: {caveats['path_form_split']}")
        # render any further provenance keys generically (data, not hardcoded prose)
        for k, v in caveats.items():
            if k not in ("floor", "recommended_floor", "path_form_split"):
                lines.append(f"- {k}: {v}")
    return "\n".join(lines)
