from sigmaforge.config import AppConfig


def test_backtest_config_defaults_and_override():
    c = AppConfig()
    assert c.backtest.floor == 1000
    assert c.backtest.attack_corpus is None  # no repo-data path baked into the pip default
    c2 = AppConfig.model_validate({"backtest": {"floor": 500, "attack_corpus": "/x"}})
    assert c2.backtest.floor == 500 and c2.backtest.attack_corpus == "/x"
