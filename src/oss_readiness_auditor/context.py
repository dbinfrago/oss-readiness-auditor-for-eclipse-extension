# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Everything a check may use. Checks receive it explicitly; there is no other shared state."""

from dataclasses import dataclass, field


@dataclass
class Context:
    repo: object  # repo.Repo: the files of the audited repository
    config: object  # config.Config: effective configuration, with the inferred project facts filled in
    components: object  # components.Components: units, own name prefixes, internal dependency graph
    npm_locks: dict = field(default_factory=dict)  # lockfile -> {package: {version, license}}
    maven_deps: list = field(default_factory=list)  # direct Maven dependencies of the repository's POMs
    third_party: dict = field(default_factory=dict)  # (ecosystem, name, version) -> sources
    committed_jars: list = field(default_factory=list)  # jars tracked in the repository (inventory.products)
    product_names: list = field(default_factory=list)  # product names the name patterns were inferred from
    results: dict = field(default_factory=dict)  # check id -> findings.Check of the checks run so far
    osv_info: list = field(default_factory=list)  # vulnerability dumps used (written by the vulnerability check)
