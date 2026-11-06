"""YAML loading for untrusted files: no anchors or aliases, and a bounded node count.

`yaml.safe_load` shares an aliased node, so a few hundred bytes of nested aliases ("billion laughs")
expand into gigabytes the moment anything walks or `str()`s the result. Sigma rules, the COMISET
mapping and the config do not need aliases, so they are refused outright. A node budget bounds the
structure memory a small file can claim (a deeply or widely nested flow collection).
"""

from __future__ import annotations

import yaml


class YamlAliasError(yaml.YAMLError):
    """The document uses an anchor or alias (value-free)."""


class YamlTooComplexError(yaml.YAMLError):
    """The document has more YAML nodes than the budget allows (value-free)."""


def _make_loader(max_nodes: int | None):
    class _Loader(yaml.SafeLoader):
        nodes = 0

        def compose_node(self, parent, index):
            ev = self.peek_event()
            # an AliasEvent carries the anchor it refers to, so this rejects both anchors and aliases
            if getattr(ev, "anchor", None) is not None:
                raise YamlAliasError("anchors and aliases are not allowed")
            self.nodes += 1
            if max_nodes is not None and self.nodes > max_nodes:
                raise YamlTooComplexError("too many YAML nodes")
            return super().compose_node(parent, index)

    return _Loader


def load_all(text: str, max_nodes: int | None = None) -> tuple[list, int]:
    """All documents of `text` and the number of YAML nodes they hold. Raises `YamlAliasError`,
    `YamlTooComplexError` or `yaml.YAMLError`."""
    loader = _make_loader(max_nodes)(text)
    try:
        docs = []
        while loader.check_data():
            docs.append(loader.get_data())
        return docs, loader.nodes
    finally:
        loader.dispose()


def load(text: str, max_nodes: int | None = None):
    """The first document of `text` (like `yaml.safe_load`), or None for an empty stream."""
    loader = _make_loader(max_nodes)(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
