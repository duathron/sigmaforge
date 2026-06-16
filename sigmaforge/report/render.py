def render_report(
    rows: list[dict], funnel: dict, source: str = "COMISET", min_events: int = 1000, fp_tuning_threshold: int = 5
) -> str:
    """A10/A8: the deliverable. A human-readable FP-tuning report.
    Leads with the site-scope + noisy-label caveat; precision labelled precision@SOURCE."""
    lines = [
        f"# Sigmaforge backtest report ({source})",
        "",
        f"> Precision is **precision@{source}**, measured on ONE university network "
        f"({source}) — not a general/cross-environment false-positive rate. "
        f"Labels are NOISY ground truth (rule-pattern attributions, e.g. OneDrive.exe tagged "
        f"as an ATT&CK technique), so a measured FP may be a mislabel. Recall is measured on "
        f"the labeled native-EVTX attack corpora. Precision floor: {min_events} evaluated events.",
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
        "| rule | recall | precision@" + source + " | tp | fp | events_evaluated |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r.get('rule')} | {r.get('recall')} | {r.get('precision@' + source, r.get('precision'))} "
            f"| {r.get('tp')} | {r.get('fp')} | {r.get('events_evaluated')} |"
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
    return "\n".join(lines)
