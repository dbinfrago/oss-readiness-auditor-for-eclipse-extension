# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import re

ID = "project-basics"
GROUP = "project"
TITLE = "Project basics and governance"
ICON = "house"
# Why the check matters for publication
WHY = "Without a license, maintainers and a way to report issues, nobody can use or contribute safely."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = "Add the missing files; LICENSE and README are the minimum."

BASICS = [
    ("LICENSE", r"(?i)^(LICEN[CS]E|COPYING)([.-]\w+)?$"),
    ("README", r"(?i)^README(\.\w+)?$"),
    ("CONTRIBUTING", r"(?i)^CONTRIBUTING(\.\w+)?$"),
    ("SECURITY", r"(?i)^SECURITY(\.\w+)?$"),
    ("CODE_OF_CONDUCT", r"(?i)^CODE[_-]OF[_-]CONDUCT(\.\w+)?$"),
    ("MAINTAINERS", r"(?i)^(MAINTAINERS|GOVERNANCE|CODEOWNERS)(\.\w+)?$"),
    ("NOTICE", r"(?i)^NOTICE(\.\w+)?$"),
]


# Settings of this check ([checks.project-basics] in the configuration)
OPTIONS = {
    "required": {
        "default": ["LICENSE", "README"],
        "choices": [name for name, _ in BASICS],
        "about": "files that must exist (blocker if missing); the others are expected (needs judgement)",
    },
}


def run(ctx, c):
    repo = ctx.repo
    required = set(ctx.config.check_option(ID, "required"))
    c.rule(
        "Files",
        "Presence of the files below in the repository root (or .github/ / docs/ for the community files). "
        "Required (blocker if missing): "
        + (", ".join(sorted(required)) or "none")
        + " – setting checks.project-basics.required.",
    )
    present = 0
    rows = []
    roots = {f.split("/")[-1]: f for f in repo.files if f.count("/") == 0 or f.startswith((".github/", "docs/"))}
    missing_required = 0
    for name, rx in BASICS:
        req = name in required
        hit = next((p for b, p in roots.items() if re.match(rx, b)), None)
        rows.append([name, "yes" if hit else "missing", "required" if req else "expected"])
        if hit:
            present += 1
            c.add(hit, None, name, "present", issue=False)
        elif c.add("(repository root)", None, f"{name} missing", "missing", level=None if req else "judgement"):
            missing_required += req
    c.figure = f"{present}/{len(BASICS)}"
    c.figure_label = "project files present"
    c.finding = "Files every open-source project is expected to have."
    c.tables.append({"caption": "Project files", "columns": ["File", "Present", "Need"], "rows": rows})
    c.status = "blocker" if missing_required else ("judgement" if c.evidence_total > present else "clear")
    return c
