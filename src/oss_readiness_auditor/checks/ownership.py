# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import re

from ..common import CODE_EXT, ext, line_index, line_of, snippet

ID = "ownership"
GROUP = "security"
TITLE = "Ownership and confidentiality notices"
ICON = "stamp"
# Why the check matters for publication
WHY = "An open tool cannot stamp an owner or a confidentiality label on its users' documents."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = "Remove ownership and confidentiality labels – especially from templates of generated documents."


def run(ctx, c):
    repo = ctx.repo
    pats = ctx.config.pack_values("ownership")
    docs = ctx.config.pack_values("ownership_outside_code", False)
    rx = re.compile("|".join(f"(?:{p})" for p in pats), re.I)
    rx_all = re.compile("|".join(f"(?:{p})" for p in pats + docs), re.I)
    c.rule(
        "Notices",
        "Any of "
        + " | ".join(f"/{p}/" for p in pats)
        + " in text files (packs: "
        + ", ".join(p for p in ctx.config.active_packs if p.startswith("lang-"))
        + "). Proprietary license headers are "
        "reported by the license check, not here.",
    )
    if docs:
        c.rule(
            "Outside code",
            "Also, in files that are not code or schema documentation ("
            + ", ".join(sorted(CODE_EXT))
            + ", .exsd): "
            + " | ".join(f"/{p}/" for p in docs)
            + " – in code it describes API visibility.",
        )
    n = 0
    for f in repo.files:
        t = repo.text(f)
        if not t:
            continue
        starts = None
        lines = set()
        for m in (rx if ext(f) in CODE_EXT | {".exsd"} else rx_all).finditer(t):
            starts = starts or line_index(t)
            ln = line_of(starts, m.start())
            if ln in lines:
                continue
            lines.add(ln)
            n += c.add(f, ln, snippet(t, starts, ln), "notice")
    c.figure = str(n)
    c.figure_label = "ownership or confidentiality notices"
    c.finding = (
        f"{n} notices that mark content as owned by someone or confidential. Notices in templates of generated "
        "documents end up in every user's output."
        if n
        else "No ownership or confidentiality notices found."
    )
    c.status = "judgement" if n else "clear"
    return c
