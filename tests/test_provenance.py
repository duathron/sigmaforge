"""Provenance block is structural metadata (values are env-dependent) — assert shape,
not values, so the test is machine-independent (the whole point of the block)."""

from sigmaforge.provenance import engine_provenance, environment_block, provenance


def test_environment_block_shape():
    env = environment_block()
    assert isinstance(env["python_version"], str) and env["python_version"]
    assert isinstance(env["platform"], str) and env["platform"]
    assert isinstance(env["sqlite_version"], str) and env["sqlite_version"]
    deps = env["engine_deps"]
    # every queried engine dep is reported (a real version or the explicit "absent")
    for name in ("pysigma", "pysigma-backend-sqlite", "orjson", "lxml"):
        assert name in deps and isinstance(deps[name], str) and deps[name]


def test_engine_provenance_keys_present_even_without_git(tmp_path):
    # engine_home with no Zircolite/git checkout -> graceful "unavailable", not a crash
    prov = engine_provenance(engine_home=str(tmp_path))
    assert "unavailable" in prov["zircolite_commit_sha"]
    assert prov["zircolite_tag"] == "unavailable"


def test_provenance_merges_engine_and_environment(tmp_path):
    p = provenance(engine_home=str(tmp_path))
    assert "zircolite_commit_sha" in p and "environment" in p
    assert "engine_deps" in p["environment"]
