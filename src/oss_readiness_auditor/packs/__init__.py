# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Built-in rule packs: knowledge grouped so that a run documents exactly what it used.

Each pack is a TOML data file next to this module: `about`, `default` (active without configuration), optionally
`locked` (cannot be disabled), and rule data – lists of regular expressions or host names, tables such as
bundle_to_maven – and [checks.<id>] tables with default settings of checks (see config.Config). Checks read the values of all active packs through Config.pack_values / Config.pack_mapping.
Default packs are generic; optional packs carry domain knowledge and are enabled per project.
"""

import tomllib
from importlib import resources

# Order matters: patterns of earlier packs are tried first, and lists are concatenated in this order.
ORDER = ("core", "eclipse", "emf", "lang-en", "lang-fr", "lang-de", "rail", "openrail")


def _load():
    base = resources.files(__name__)
    return {name: tomllib.loads(base.joinpath(f"{name}.toml").read_text(encoding="utf-8")) for name in ORDER}


PACKS = _load()
