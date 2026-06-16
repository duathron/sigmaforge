from sigmaforge.report.render import render_report


def test_report_has_funnel_site_label_and_tuning():
    rows = [
        {
            "rule": "PowerShell Enc",
            "recall": 1.0,
            "precision@COMISET": 0.2,
            "tp": 5,
            "fp": 20,
            "events_evaluated": 50000,
        }
    ]
    funnel = {"candidate": 100, "loaded": 95, "stateless": 90, "fires": 40, "survives_fp": 12}
    md = render_report(rows, funnel, source="COMISET", min_events=1000)
    assert "precision@COMISET" in md
    assert "one university network" in md.lower()
    assert "noisy" in md.lower()
    assert "candidate: 100" in md
    assert "fires 20x on benign" in md  # the FP-tuning line surfaces the over-broad rule


def test_report_no_tuning_candidates():
    rows = [{"rule": "Tight", "recall": 1.0, "precision@COMISET": 1.0, "tp": 2, "fp": 0, "events_evaluated": 9000}]
    md = render_report(rows, {"candidate": 1}, min_events=1000)
    assert "none above threshold" in md
