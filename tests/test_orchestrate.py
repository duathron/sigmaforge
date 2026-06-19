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
    assert "precision@COMISET" in md and "benign corpus described below" in md.lower()
    assert "run hash" in md.lower()  # A11 wiring guarded (mutation to run_hash=None must fail here)


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


def test_no_benign_exemplars_flag_set_when_precision_is_tautological():
    # BLOCKER-2: rule fires only on a malicious-labelled event; the benign corpus has
    # ZERO benign-labelled events carrying the rule's selection field (Image) ->
    # precision computes to 1.0 but carries no FP signal -> flagged.
    # benign-labelled events do NOT carry Image (0 benign exemplars); malicious-labelled ones do,
    # enough of them to clear the coverage floor so precision is actually computed (and tautological).
    benign_events = [{"OtherField": "x", "sigmaforge_label": "benign"} for _ in range(2000)]
    benign_events += [{"Image": "x", "sigmaforge_label": "malicious"} for _ in range(1500)]
    benign = {MatchRecord("PowerShell Enc", "m0", "malicious")}
    rows, _, md = run_backtest(
        [RULE],
        set(),
        benign,
        benign_events,
        n_attack_events=1533,
        positive_control_fired=True,
        min_events=1000,
    )
    r = rows[0]
    assert r["benign_events_evaluated"] == 0
    assert r["no_benign_exemplars"] is True
    assert r["precision@COMISET"] == 1.0  # tautological 1.0
    assert r["fp"] == 0
    # report must flag it, not present it as FP-resistance
    assert "no benign exemplars" in md.lower()
    assert "no-benign-exemplars" in md.lower()


def test_real_precision_signal_when_benign_exemplars_present():
    # contrast: benign-labelled events DO carry the selection field -> real FP signal
    benign_events = [{"Image": "x", "sigmaforge_label": "benign"} for _ in range(2000)]
    rows, _, _ = run_backtest(
        [RULE],
        set(),
        {MatchRecord("PowerShell Enc", "b0", "benign")},
        benign_events,
        n_attack_events=1533,
        positive_control_fired=True,
        min_events=1000,
    )
    r = rows[0]
    assert r["benign_events_evaluated"] == 2000
    assert r["no_benign_exemplars"] is False


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


# --- FIX B: per-technique recall in the orchestrator -------------------------

TAGGED_RULE = {
    "title": "PowerShell Enc",
    "tags": ["attack.execution", "attack.t1059.001"],  # FIX B2: kept granular -> T1059.001
    "detection": {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"},
}
UNTAGGED_RULE = {
    "title": "No Tag Rule",
    "detection": {"selection": {"Image|endswith": "\\x.exe"}, "condition": "selection"},
}
OTHER_TECH_RULE = {
    "title": "Other Tech Rule",
    "tags": ["attack.t1490"],  # technique with ZERO attack events in our map
    "detection": {"selection": {"Image|endswith": "\\y.exe"}, "condition": "selection"},
}


def test_per_technique_recall_scopes_denominator_to_the_rules_technique():
    # 100 T1059.001 attack events exist; the rule (tagged T1059.001) fired on 3 of them
    # -> recall 3/100, NOT 3/(whole corpus). Sibling T1059.003 + off-technique T1003 do
    # NOT enlarge the denominator (FIX B2: no sibling dilution).
    attack = {MatchRecord("PowerShell Enc", f"e{i}", "malicious") for i in range(3)}
    event_technique = {f"e{i}": "T1059.001" for i in range(3)}
    technique_event_counts = {"T1059.001": 100, "T1059.003": 140, "T1003": 9999}
    rows, _, md = run_backtest(
        [TAGGED_RULE],
        attack,
        set(),
        _benign_events(),
        n_attack_events=10239,  # legacy pooled denom — must be IGNORED in per-technique mode
        positive_control_fired=True,
        min_events=1000,
        event_technique=event_technique,
        technique_event_counts=technique_event_counts,
    )
    r = rows[0]
    assert r["recall"] == 3 / 100  # scoped to T1059.001 (siblings/off-tech excluded)
    assert r["recall_denom"] == 100  # NOT 100+140 — T1059.003 siblings excluded
    assert r["recall_numer"] == 3
    assert r["recall_measurable"] is True
    assert r["recall_measured_techniques"] == ["T1059.001"]
    assert "per-technique" in md.lower()


def test_per_technique_recall_ignores_fires_on_off_technique_events():
    # rule's technique is T1059.001; it fired on one T1059.001 event and one T1003 event.
    # only the on-technique fire counts toward this rule's recall.
    attack = {
        MatchRecord("PowerShell Enc", "good", "malicious"),
        MatchRecord("PowerShell Enc", "wrong", "malicious"),
    }
    event_technique = {"good": "T1059.001", "wrong": "T1003"}
    technique_event_counts = {"T1059.001": 10, "T1003": 10}
    rows, _, _ = run_backtest(
        [TAGGED_RULE],
        attack,
        set(),
        _benign_events(),
        n_attack_events=20,
        positive_control_fired=True,
        min_events=1000,
        event_technique=event_technique,
        technique_event_counts=technique_event_counts,
    )
    r = rows[0]
    assert r["recall_numer"] == 1  # only the T1059 fire
    assert r["recall"] == 1 / 10


def test_untagged_rule_is_unmeasured_not_zero():
    rows, _, _ = run_backtest(
        [UNTAGGED_RULE],
        set(),
        set(),
        _benign_events(),
        n_attack_events=100,
        positive_control_fired=True,
        min_events=1000,
        event_technique={"e0": "T1059"},
        technique_event_counts={"T1059": 100},
    )
    r = rows[0]
    assert r["recall"] == "unmeasured"  # NOT 0.0, NOT pooled
    assert r["recall_measurable"] is False


def test_technique_with_zero_attack_events_is_unmeasured():
    # rule tagged T1490, but the corpus has ZERO T1490 attack events -> unmeasured.
    rows, _, _ = run_backtest(
        [OTHER_TECH_RULE],
        set(),
        set(),
        _benign_events(),
        n_attack_events=100,
        positive_control_fired=True,
        min_events=1000,
        event_technique={"e0": "T1059"},
        technique_event_counts={"T1059": 100},  # no T1490 key -> 0 events
    )
    r = rows[0]
    assert r["recall"] == "unmeasured"
    assert r["recall_measurable"] is False


def test_pooled_fallback_when_technique_inputs_absent():
    # no per-technique inputs -> legacy pooled denominator, recall_measurable=None
    attack = {MatchRecord("PowerShell Enc", f"e{i}", "malicious") for i in range(3)}
    rows, _, _ = run_backtest(
        [TAGGED_RULE],
        attack,
        set(),
        _benign_events(),
        n_attack_events=1533,
        positive_control_fired=True,
        min_events=1000,
    )
    r = rows[0]
    assert r["recall"] == 3 / 1533  # pooled
    assert r["recall_measurable"] is None


# --- C2 Task 2.3: reason-codes threaded onto rows + recall_mode on funnel ------


def test_recall_mode_per_technique_when_inputs_present():
    attack = {MatchRecord("PowerShell Enc", "e0", "malicious")}
    rows, funnel, _ = run_backtest(
        [TAGGED_RULE],
        attack,
        set(),
        _benign_events(),
        n_attack_events=100,
        positive_control_fired=True,
        min_events=1000,
        event_technique={"e0": "T1059.001"},
        technique_event_counts={"T1059.001": 100},
    )
    assert funnel["recall_mode"] == "per-technique"
    # measured row -> no recall_reason. The rule never fired on the benign corpus
    # (benign_fires empty) yet the 5000 events clear the floor: precision is unmeasured
    # with a ZERO denominator, so its reason is no-benign-exemplars (not below-floor).
    assert rows[0]["recall_reason"] is None
    assert rows[0]["precision_reason"] == "no-benign-exemplars"


def test_recall_mode_pooled_when_inputs_absent():
    rows, funnel, _ = run_backtest(
        [TAGGED_RULE],
        set(),
        set(),
        _benign_events(),
        n_attack_events=100,
        positive_control_fired=True,
        min_events=1000,
    )
    assert funnel["recall_mode"] == "pooled"
    # pooled mode: recall is not per-technique-measured -> no reason-code threaded
    assert rows[0]["recall_reason"] is None


def test_recall_reason_no_tag_threaded_onto_row():
    rows, _, _ = run_backtest(
        [UNTAGGED_RULE],
        set(),
        set(),
        _benign_events(),
        n_attack_events=100,
        positive_control_fired=True,
        min_events=1000,
        event_technique={"e0": "T1059"},
        technique_event_counts={"T1059": 100},
    )
    assert rows[0]["recall_reason"] == "no-tag"


def test_recall_reason_technique_zero_events_threaded_onto_row():
    rows, _, _ = run_backtest(
        [OTHER_TECH_RULE],
        set(),
        set(),
        _benign_events(),
        n_attack_events=100,
        positive_control_fired=True,
        min_events=1000,
        event_technique={"e0": "T1059"},
        technique_event_counts={"T1059": 100},  # no T1490 -> denom 0
    )
    assert rows[0]["recall_reason"] == "technique-0-events"


def test_precision_reason_none_above_floor():
    # benign-labelled events carry the selection field, enough to clear the floor
    benign_events = [{"Image": "x", "sigmaforge_label": "benign"} for _ in range(2000)]
    rows, _, _ = run_backtest(
        [RULE],
        set(),
        {MatchRecord("PowerShell Enc", "b0", "benign")},
        benign_events,
        n_attack_events=1,
        positive_control_fired=True,
        min_events=1000,
    )
    assert rows[0]["precision_reason"] is None


def test_precision_reason_below_floor_threaded_onto_row():
    # only 10 benign events carry the selection field -> below the 1000 floor
    benign_events = [{"Image": "x", "sigmaforge_label": "benign"} for _ in range(10)]
    rows, _, _ = run_backtest(
        [RULE],
        set(),
        set(),
        benign_events,
        n_attack_events=1,
        positive_control_fired=True,
        min_events=1000,
    )
    assert rows[0]["precision_reason"] == "below-floor"
