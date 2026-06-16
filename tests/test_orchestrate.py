from sigmaforge.orchestrate import run_backtest
from sigmaforge.records import MatchRecord

RULE = {
    "title": "PowerShell Enc",
    "detection": {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"},
}


def test_two_source_scoring_and_report():
    # attack corpus: rule fired on 3 malicious events (recall); 4 total attack events
    attack = {MatchRecord("PowerShell Enc", f"a{i}", "malicious") for i in range(3)}
    # benign corpus: rule fired on 2 benign events (FP)
    benign = {MatchRecord("PowerShell Enc", f"b{i}", "benign") for i in range(2)}
    benign_events = [{"Image": "x"} for _ in range(5000)]  # all carry the selection field

    rows, funnel, md = run_backtest(
        [RULE],
        attack,
        benign,
        benign_events,
        n_attack_malicious=4,
        positive_control_fired=True,
        min_events=1000,
    )
    r = rows[0]
    assert r["tp"] == 3 and r["fp"] == 2
    assert r["recall"] == 3 / 4
    assert r["precision@COMISET"] == 3 / 5  # tp/(tp+fp), above floor + control fired
    assert "precision@COMISET" in md and "one university network" in md.lower()


def test_precision_blocked_when_control_fails():
    attack = {MatchRecord("PowerShell Enc", "a0", "malicious")}
    benign = {MatchRecord("PowerShell Enc", "b0", "benign")}
    rows, _, _ = run_backtest(
        [RULE],
        attack,
        benign,
        [{"Image": "x"}] * 5000,
        n_attack_malicious=1,
        positive_control_fired=False,
        min_events=1000,
    )
    assert rows[0]["precision@COMISET"] == "unmeasured"  # mapping/control broke
