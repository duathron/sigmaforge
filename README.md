# sigmaforge

Honest Sigma-rule backtest harness

## Install
    pip install sigmaforge

## Usage
    sigmaforge classify 8.8.8.8
    sigmaforge version

## Development
Built with the [Shipwright](https://github.com/duathron/shipwright) framework.

    uv sync --dev
    uv run pre-commit install
    just lint && just test && just dogfood

## License
MIT (c) Christian Huhn
