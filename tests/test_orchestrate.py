from sigmaforge.orchestrate import run_backtest
from sigmaforge.records import MatchRecord

RULE = {
    "title": "PowerShell Enc",
    "detection": {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"},
}


def _benign_events():
    # 4999 benign + 1 malicious-labelled event (COMISET mixes ~0.3% malicious into the benign corpus)
    events = [{"Image": "x", "sigmaforge_label": "benign"} for _ in range(4999)]
    events.append({"Image": "x", "sigmaforge_label": "malicious"})
    return events


def test_two_source_label_aware_scoring():
    # recall side: attack corpus, rule fired on 3 malicious events; 4 total attack events -> recall 3/4
    attack = {MatchRecord("PowerShell Enc", f"a{i}", "malicious") for i in range(3)}
    # precision side: rule fired on 2 benign-labelled events (FP) + 1 malicious-labelled (TP, A3)
    benign = {
        MatchRecord("PowerShell Enc", "b0", "benign"),
        MatchRecord("PowerShell Enc", "b1", "benign"),
        MatchRecord("PowerShell Enc", "m0", "malicious"),
    }
    rows, funnel, md = run_backtest(
        [RULE],
        attack,
        benign,
        _benign_events(),
        n_attack_events=4,
        positive_control_fired=True,
        min_events=1000,
    )
    r = rows[0]
    assert r["recall"] == 3 / 4
    assert r["tp"] == 1 and r["fp"] == 2  # A3: the malicious benign-corpus hit is TP, not FP
    assert r["precision@COMISET"] == 1 / 3  # 1/(1+2)
    assert "precision" not in r  # A2: no ungated raw precision leaks
    assert "precision@COMISET" in md and "one university network" in md.lower()


def test_duplicate_benign_fires_deduped():
    # MAJOR-5: same event fired twice must not inflate fp (score_rule is now the live path)
    attack: set[MatchRecord] = set()
    benign = {MatchRecord("PowerShell Enc", "b0", "benign"), MatchRecord("PowerShell Enc", "b0", "benign")}
    rows, _, _ = run_backtest(
        [RULE],
        attack,
        benign,
        _benign_events(),
        n_attack_events=10,
        positive_control_fired=True,
        min_events=1000,
    )
    assert rows[0]["fp"] == 1  # deduped, not 2


def test_precision_blocked_when_control_fails():
    benign = {MatchRecord("PowerShell Enc", "b0", "benign")}
    rows, _, _ = run_backtest(
        [RULE],
        set(),
        benign,
        _benign_events(),
        n_attack_events=1,
        positive_control_fired=False,
        min_events=1000,
    )
    assert rows[0]["precision@COMISET"] == "unmeasured"  # mapping/control broke -> A2 block
