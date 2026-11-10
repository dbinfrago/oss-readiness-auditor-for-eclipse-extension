# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""The checks, in report order.

Every check is a module with the same shape:

    ID, GROUP, TITLE, ICON   identification and report placement
    WHY                      why the check matters for publication
    RESOLVE                  what resolves its findings, in plain words
    run(ctx, c)              fills the check `c` (rules, findings, figure, status) from the context `ctx` and
                             returns it, or returns None when the check does not apply (its rule pack is not active)

Optional: OPTIONS (settings of the check, configurable in [checks.<ID>]) and PACK (the rule pack it needs).
Every check also accepts the settings `enabled` and `level` (see config.LEVELS).

A check reads only the context (context.Context) and its own module; the rules it applies are documented with
c.rule(...) and appear in every report.
"""

from . import (
    domain_data,
    eclipse_metadata,
    internal_hosts,
    license_notices,
    name_logo,
    namespace,
    openrail,
    ownerless,
    ownership,
    personal_data,
    project_basics,
    remnants,
    reuse_dco,
    secrets,
    third_party,
    vulnerabilities,
)

ALL = (
    license_notices,
    ownerless,
    remnants,
    eclipse_metadata,
    name_logo,
    namespace,
    third_party,
    vulnerabilities,
    secrets,
    internal_hosts,
    domain_data,
    personal_data,
    ownership,
    project_basics,
    reuse_dco,
    openrail,
)
