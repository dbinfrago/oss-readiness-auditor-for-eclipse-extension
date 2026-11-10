# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import fnmatch
import os
import re

from ..headers import HEADER_CHARS, SPDX_LIC

ID = "reuse-dco"
GROUP = "project"
TITLE = "License header on every file (REUSE standard) and commit sign-off (DCO)"
ICON = "clipboard-check"
# Why the check matters for publication
WHY = (
    "REUSE (FSFE standard) means every file states its copyright holder and license in a machine-readable way, so "
    "anyone can reuse any file safely. DCO sign-off means every contributor certifies their right to contribute."
)
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "Add a license and copyright header (SPDX) to every file, or declare it in REUSE.toml; put the license texts in "
    "LICENSES/; check with the 'reuse lint' tool. Contributors sign off their commits (git commit -s)."
)


# Settings of this check ([checks.reuse-dco] in the configuration)
OPTIONS = {
    "reuse": {
        "default": "judgement",
        "choices": ["blocker", "judgement"],
        "about": "files without REUSE license information",
    },
    "dco": {"default": "judgement", "choices": ["blocker", "judgement"], "about": "commits without sign-off"},
}


def reuse_annotations(repo):
    globs = []
    for f in ("REUSE.toml",):
        if f in repo.files:
            for m in re.finditer(r'(?m)^\s*path\s*=\s*(\[[^\]]*\]|"[^"]*")', repo.text(f) or ""):
                globs += re.findall(r'"([^"]+)"', m.group(1))
    dep5 = ".reuse/dep5"
    if dep5 in repo.files:
        for m in re.finditer(r"(?m)^Files:\s*(.+)$", repo.text(dep5) or ""):
            globs += m.group(1).split()
    return globs


EXEMPT = re.compile(r"(?i)^(LICEN[CS]E|COPYING)([-.].*)?$")


def has_reuse_info(repo, f, globs, side):
    """True if the file declares its license the REUSE way (or needs not: license texts, side-car files)."""
    if f.endswith(".license") or f.startswith("LICENSES/") or EXEMPT.match(os.path.basename(f)):
        return True
    t = repo.text(f, include_self=True)
    return bool((t and SPDX_LIC.search(t[:HEADER_CHARS])) or f in side or any(fnmatch.fnmatch(f, g) for g in globs))


def reuse_coverage(repo):
    """(covered, total) files, without acknowledgements."""
    globs = reuse_annotations(repo)
    side = {f[:-8] for f in repo.files if f.endswith(".license")}
    return sum(1 for f in repo.files if has_reuse_info(repo, f, globs, side)), len(repo.files)


def run(ctx, c):
    repo = ctx.repo
    pol = {k: ctx.config.check_option(ID, k) for k in ("reuse", "dco")}
    c.rule(
        "REUSE coverage",
        "A file is covered if it has an SPDX-"
        "License-Identifier in its first lines, a .license "
        "side-car file, or matches a path in REUSE.toml / .reuse/dep5 (simplified glob matching). Below 100 %: "
        f"{pol['reuse']} (setting checks.reuse-dco.reuse).",
    )
    c.rule(
        "Not a compliance verdict",
        "This is a coverage estimate. The REUSE specification has further requirements (valid SPDX expressions, a "
        "license text for every license used, ignore markers); confirm compliance with the official tool: "
        "'reuse lint' (https://reuse.software).",
    )
    c.rule(
        "License texts",
        "LICENSES/ folder with the texts of all licenses used. LICENSE/COPYING files are exempt, "
        "as in the REUSE specification.",
    )
    c.rule(
        "DCO",
        "Share of commits whose message contains 'Signed-off-by:' (git history). Below 100 %: "
        f"{pol['dco']} (setting checks.reuse-dco.dco).",
    )
    globs = reuse_annotations(repo)
    covered = 0
    side = {f[:-8] for f in repo.files if f.endswith(".license")}
    for f in repo.files:
        if has_reuse_info(repo, f, globs, side):
            covered += 1
        elif not c.add(f, None, "", "no license information", level=None if pol["reuse"] == "blocker" else "judgement"):
            covered += 1
    total = len(repo.files)
    lic_dir = sorted(f for f in repo.files if f.startswith("LICENSES/"))
    log = repo.git_log_bodies()
    signed = sum(1 for _, b in log if "Signed-off-by:" in b) if log else None
    pct = 100.0 * covered / total if total else 0
    c.figure = f"{pct:.0f} %"
    c.figure_label = f"of {total:,} files declare their license the REUSE way ({covered:,}) – confirm with 'reuse lint'"
    c.finding = f"REUSE: {covered:,} of {total:,} files covered; LICENSES/ has {len(lic_dir)} license text(s). " + (
        f"DCO: {signed} of {len(log)} commits signed off." if log is not None else "DCO: no git history available."
    )
    c.tables.append(
        {
            "caption": "Summary",
            "columns": ["Item", "Value"],
            "rows": [
                ["Files covered by REUSE", f"{covered:,} / {total:,}"],
                ["License texts in LICENSES/", ", ".join(os.path.basename(x) for x in lic_dir) or "none"],
                ["Commits signed off", f"{signed} / {len(log)}" if log is not None else "n/a"],
            ],
        }
    )
    for f in lic_dir:
        c.add(f, None, "", "license text", issue=False)
    reuse_gap, dco_gap = covered < total, bool(log) and signed < len(log)
    if (reuse_gap and pol["reuse"] == "blocker") or (dco_gap and pol["dco"] == "blocker"):
        c.status = "blocker"
    else:
        c.status = "judgement" if reuse_gap or dco_gap else "clear"
    return c
