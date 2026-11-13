# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
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
    c.rule(
        "LICENSE as REUSE texts",
        "Without a root LICENSE file, license texts in LICENSES/ (REUSE layout) declare the license: they are "
        "reported as detected, the missing root LICENSE file needs judgement, not a blocker. GitHub advises a "
        "LICENSE file in the repository root – only from there does it detect and display the repository's license; "
        "other platforms and scanners do the same.",
    )
    present = 0
    rows = []
    roots = {f.split("/")[-1]: f for f in repo.files if f.count("/") == 0 or f.startswith((".github/", "docs/"))}
    reuse_texts = sorted(f for f in repo.files if f.startswith("LICENSES/") and f.count("/") == 1)
    reuse_ids = ", ".join(os.path.splitext(os.path.basename(f))[0] for f in reuse_texts)
    root_license_missing = False
    missing_required = 0
    for name, rx in BASICS:
        req = name in required
        hit = next((p for b, p in roots.items() if re.match(rx, b)), None)
        if not hit and name == "LICENSE" and reuse_texts:
            root_license_missing = True
            rows.append(
                [name, f"detected in LICENSES/ ({reuse_ids}); root LICENSE missing", "required" if req else "expected"]
            )
            for f in reuse_texts:
                c.add(f, None, "license text detected", "LICENSES/", issue=False)
            c.add(
                "(repository root)",
                None,
                "LICENSE missing in the root – GitHub advises one there to detect and display the license",
                "root LICENSE missing",
                level="judgement",
            )
            continue
        rows.append([name, "yes" if hit else "missing", "required" if req else "expected"])
        if hit:
            present += 1
            c.add(hit, None, name, "present", issue=False)
        elif c.add("(repository root)", None, f"{name} missing", "missing", level=None if req else "judgement"):
            missing_required += req
    c.figure = f"{present}/{len(BASICS)}"
    c.figure_label = "project files present" + (" · license detected in LICENSES/" if root_license_missing else "")
    c.finding = "Files every open-source project is expected to have." + (
        f" The license is detected in LICENSES/ ({reuse_ids}), but the repository root has no LICENSE file. "
        "GitHub advises one in the root: only from there does it detect the license and show it on the repository "
        "page. Copy the main license text to LICENSE (and declare it in REUSE.toml or a .license file)."
        if root_license_missing
        else ""
    )
    c.tables.append({"caption": "Project files", "columns": ["File", "Present", "Need"], "rows": rows})
    gaps = c.evidence_total - present - (len(reuse_texts) if root_license_missing else 0)
    c.status = "blocker" if missing_required else ("judgement" if gaps else "clear")
    return c
