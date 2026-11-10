# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Runs all checks and assembles the report data."""

import datetime
import hashlib
import json
import os
import platform
import sys

from . import TOOL_NAME, TOOL_VERSION
from .checks import ALL
from .components import Components
from .config import LEVELS
from .context import Context
from .findings import GROUPS, Check
from .infer import infer_name_patterns
from .inventory.maven import maven_deps
from .inventory.npm import npm_locks
from .inventory.products import committed_jars, product_components


def resolve_project(repo, config):
    """Fill in the project facts that the configuration leaves open, by inference from the repository.
    Returns the components and the product names the name patterns were inferred from."""
    components = Components(
        repo,
        [os.path.basename(os.path.normpath(p)) for p in config.products],
        config.project["own_prefixes"],
        config.move_out,
        config.project["family_depth"],
    )
    if components.own_inferred:
        config.project["own_prefixes"], config.source["own_prefixes"] = list(components.own), "inferred"
    names = []
    if config.project["name_patterns"] is None:
        pats, names = infer_name_patterns(repo)
        config.project["name_patterns"], config.source["name_patterns"] = pats, "inferred"
    return components, names


def build_report(repo, config, quiet=False):
    components, product_names = resolve_project(repo, config)
    ctx = Context(repo, config, components, npm_locks(repo), maven_deps(repo), product_names=product_names)
    for lock, pkgs in ctx.npm_locks.items():
        for n, p in pkgs.items():
            if not p.get("root") and p.get("version"):
                ctx.third_party.setdefault(("npm", n, p["version"]), set()).add(lock)
    for d in ctx.maven_deps:
        ctx.third_party.setdefault(("Maven", d["name"], d["version"]), set()).add(d["source"])
    ctx.committed_jars = committed_jars(repo, components.is_own, config.pack_mapping("bundle_to_maven"))
    for j in ctx.committed_jars:
        for k in j["components"]:
            ctx.third_party.setdefault(k, set()).add(j["file"])
    if config.products:
        found = product_components(config.products, components.own, config.pack_mapping("bundle_to_maven"))
        for k, v in found.items():
            ctx.third_party.setdefault(k, set()).update(v)
    checks, disabled = [], []
    for check in ALL:
        settings = config.check_config[check.ID]
        if not settings["enabled"][0]:
            disabled.append(check.ID)
            continue
        c = Check(ctx, check.ID, check.GROUP, check.TITLE, check.ICON, check.WHY, check.RESOLVE)
        if check.run(ctx, c) is None:  # check not applicable (its rule pack is not active)
            continue
        level, source = settings["level"]
        if level != "default":
            c.rule("Criticality", f"Set to '{level}' ({source}): {LEVELS[level]}.")
            c.apply_level(level)
        ctx.results[c.id] = c
        if not quiet:
            print(f"  {c.title:<47} {c.status:<10} {c.figure}", file=sys.stderr)
        checks.append(c.as_dict())
    data = {
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "run": {
            "time_utc": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "repository": repo.root if not config.anonymise else os.path.basename(repo.root),
            "git": repo.git,
            "files_scanned": len(repo.files),
            "files_excluded": len(repo.excluded),
            "skipped_auditor_copies": sorted(repo.skipped_self),
            "products": [os.path.basename(os.path.normpath(p)) for p in config.products],
            "osv": ctx.osv_info,
            "components": len(ctx.third_party),
            "modules": sum(
                1 for u in components.units.values() if u["kind"] not in ("repository", "folder", "product")
            ),
        },
        "config": config.summary() | {"disabled_checks": disabled},
        "groups": GROUPS,
        "checks": checks,
        "components": components.export(checks),
    }
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False)
    data["run"]["data_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return data
