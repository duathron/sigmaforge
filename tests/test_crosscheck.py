from sigmaforge.crosscheck.chainsaw import compare_loaded_intersection


def test_compare_only_over_intersection():
    z_loaded = {"r1", "r2", "r3"}
    c_loaded = {"r1", "r2"}  # r3 failed to load in chainsaw
    z_hits = {"r1": {"e1"}, "r2": set(), "r3": {"e9"}}
    c_hits = {"r1": {"e1"}, "r2": {"e5"}}
    result = compare_loaded_intersection(z_hits, c_hits, z_loaded, c_loaded)
    assert result["compared_rules"] == {"r1", "r2"}  # r3 excluded (load artifact)
    assert result["agree"] == {"r1"}
    assert result["disagree"] == {"r2"}
    assert result["load_artifact_only"] == {"r3"}
