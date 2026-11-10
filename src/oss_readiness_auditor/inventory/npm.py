# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""npm lockfiles."""

import json
import os


def npm_locks(repo):
    locks = {}
    for f in repo.files:
        if os.path.basename(f) != "package-lock.json" or "/node_modules/" in f:
            continue
        try:
            d = json.loads(repo.text(f) or "{}")
        except ValueError:
            continue
        pkgs = {}
        if "packages" in d:
            for path, p in d["packages"].items():
                if p.get("dev") or p.get("link"):
                    continue
                if path == "":
                    pkgs[d.get("name", "(root)")] = {
                        "version": p.get("version"),
                        "license": p.get("license"),
                        "root": True,
                    }
                    continue
                name = path.split("node_modules/")[-1]
                pkgs[name] = {"version": p.get("version"), "license": p.get("license")}
        else:  # lockfile v1

            def walk(deps, pkgs=pkgs):
                for name, p in (deps or {}).items():
                    if not p.get("dev"):
                        pkgs[name] = {"version": p.get("version"), "license": None}
                    walk(p.get("dependencies"))

            walk(d.get("dependencies"))
        locks[f] = pkgs
    return locks
