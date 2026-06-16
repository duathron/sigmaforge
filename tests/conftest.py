"""Shared test fixtures.

Record-and-replay convention (framework QA policy): when this project calls an
external API, record real responses once (vcr.py / saved JSON under
tests/fixtures/) and replay them in Tier-1 tests — never invent response dicts.
"""
