# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
import re
from collections import Counter

from ..common import ext

ID = "domain-data"
GROUP = "security"
TITLE = "Real-world domain data"
ICON = "database"
# Why the check matters for publication
WHY = "Data about real infrastructure, customers or operations may only be published with its owner's consent."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = "The data owner confirms each file may be published, or it is replaced by synthetic data."


def run(ctx, c):
    """Only run when a rule pack or the configuration defines data-file rules (e.g. the 'rail' pack: railML)."""
    repo = ctx.repo
    rules = ctx.config.pack_values("data_files")
    if not rules:
        return None
    for r in rules:
        c.rule(
            r["name"],
            "Files with extension "
            + ", ".join(r.get("extensions", []))
            + (f", or XML files whose first 4,000 characters contain a <{r['root']}> element" if r.get("root") else "")
            + (f", or paths matching /{r['path']}/" if r.get("path") else "")
            + ".",
        )
    dirs, kinds = Counter(), Counter()
    for f in repo.files:
        for r in rules:
            hit = ext(f) in [e.lower() for e in r.get("extensions", [])]
            if not hit and r.get("path"):
                hit = re.search(r["path"], f, re.I) is not None
            if not hit and r.get("root") and ext(f) == ".xml":
                hit = (
                    re.search(r"<(?:\w+:)?" + re.escape(r["root"]) + r"\b", (repo.text(f) or "")[:4000], re.I)
                    is not None
                )
            if hit:
                if c.add(f, None, "", r["name"]):
                    dirs[os.path.dirname(f) or "."] += 1
                    kinds[r["name"]] += 1
                break
    n = sum(dirs.values())
    c.figure = str(n)
    c.figure_label = f"domain data files in {len(dirs)} folders"
    c.finding = (
        f"{n} domain data files (" + ", ".join(f"{k}: {v}" for k, v in kinds.most_common()) + "). Whether "
        "they describe real-world assets is for their owner to judge; the folder names below help."
        if n
        else "No domain data files matched the rules."
    )
    c.tables.append(
        {
            "caption": "Folders with domain data files",
            "columns": ["Folder", "Files"],
            "rows": [[d, k] for d, k in dirs.most_common(30)],
        }
    )
    c.status = "judgement" if n else "clear"
    return c
