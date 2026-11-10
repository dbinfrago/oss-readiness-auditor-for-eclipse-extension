# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
from collections import Counter

from ..common import ext, line_index, line_of, snippet
from ..masking import PLACEHOLDER, SECRET_RULES, mask_secret

ID = "secrets"
GROUP = "security"
TITLE = "Credentials in the repository"
ICON = "key-round"
# Why the check matters for publication
WHY = "Published secrets stay public forever – including the history."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "Rotate every real credential, remove it from the code and from the history (publish a fresh history), and read "
    "secrets from configuration at runtime."
)

SECRET_EXT = {
    ".xml",
    ".properties",
    ".yml",
    ".yaml",
    ".json",
    ".ps1",
    ".sh",
    ".bat",
    ".cmd",
    ".ini",
    ".conf",
    ".cfg",
    ".env",
    ".java",
    ".xtend",
    ".js",
    ".ts",
    ".py",
    ".launch",
    ".product",
    ".txt",
    ".md",
    ".toml",
    ".gradle",
    ".prefs",
}


def run(ctx, c):
    repo = ctx.repo
    for name, rx, _, *only in SECRET_RULES:
        c.rule(
            name,
            "/"
            + rx.pattern
            + "/"
            + (" – only in " + ", ".join(sorted(e or "(no extension)" for e in only[0])) if only else ""),
        )
    c.rule(
        "Exclusions",
        "Values that are obviously placeholders (****, changeme, ${…}, <…>, 'password', 'test' …) are "
        f"ignored; a value matched by several rules on the same line counts once. Searched file types: {', '.join(sorted(SECRET_EXT))}, Dockerfiles and files without extension. "
        "Values are masked in this report.",
    )
    kinds = Counter()
    files = set()
    for f in repo.files:
        e = ext(f)
        if e not in SECRET_EXT and not os.path.basename(f).startswith(("Dockerfile", ".env")) and e:
            continue
        t = repo.text(f)
        if not t:
            continue
        starts = None
        seen = set()
        for name, rx, grp, *only in SECRET_RULES:
            if only and e not in only[0] and not os.path.basename(f).startswith(".env"):
                continue
            for m in rx.finditer(t):
                if grp is None:
                    val = next((g for g in m.groups() if g), m.group(0)) if m.groups() else m.group(0)
                else:
                    val = m.group(grp)
                if name != "Private key" and PLACEHOLDER.match(val or ""):
                    continue
                starts = starts or line_index(t)
                ln = line_of(starts, m.start())
                if (ln, val) in seen:
                    continue
                seen.add((ln, val))
                shown = "PRIVATE KEY block" if name == "Private key" else mask_secret(val)
                if c.add(f, ln, shown, name, match=f"{name} {snippet(t, starts, ln, 400)}"):
                    kinds[name] += 1
                    files.add(f)
    n = c.evidence_total
    c.figure = str(n)
    c.figure_label = f"possible credentials in {len(files)} files"
    c.finding = (
        "Possible credentials found: "
        + ", ".join(f"{k} {v}" for k, v in kinds.most_common())
        + ". Each must be checked; real secrets must be rotated, and the public history must never contain them."
        if n
        else "No credentials matched the rules."
    )
    c.status = "blocker" if n else "clear"
    return c
