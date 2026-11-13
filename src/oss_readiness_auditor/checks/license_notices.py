# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import re
from collections import Counter

from ..common import DOC_EXT, compiled, ext, line_index, snippet
from ..headers import (
    CODE_TEMPLATE,
    ECLIPSE_FULLTEXT,
    HEADER_CHARS,
    LICENSE_GRANT,
    SPDX_LIC,
    header_of,
    holder_name,
    locate,
    normalise,
)

ID = "license-notices"
GROUP = "legal"
TITLE = "Proprietary license notices"
ICON = "file-lock"
# Why the check matters for publication
WHY = "No license, no open source – nobody may legally use, change or share the code."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "The owners named in the clauses agree to the open-source license; the clauses are replaced by that license's "
    "header – also in code templates and generator settings, so new files stay clean."
)


def run(ctx, c):
    repo = ctx.repo
    props = compiled(ctx.config.pack_values("proprietary"), "proprietary")
    arr = re.compile("|".join(ctx.config.pack_values("all_rights", False)), re.I)
    eclipse = "eclipse" in ctx.config.active_packs
    c.rule(
        "Proprietary clause",
        "Any of these patterns (packs: " + ", ".join(ctx.config.active_packs) + "; "
        "named group 'holder' = owner) in the license header of a file – for code everything before the first "
        f"package/import statement, otherwise the first {HEADER_CHARS} characters, comment markers, markup and "
        "line breaks removed: " + " | ".join("/" + r.pattern + "/" for r in props),
    )
    c.rule(
        "Searched in full",
        "Documentation ("
        + ", ".join(sorted(DOC_EXT))
        + ")"
        + (
            " and Eclipse metadata that carries license and branding text: about.*, feature.xml/.properties, "
            "plugin.properties, bundle.properties, *.product, *.genmodel, .settings/*.prefs (code templates), "
            "license/notice files"
            if eclipse
            else ""
        )
        + ".",
    )
    c.rule(
        "All rights reserved",
        f"/{arr.pattern}/ in the header of a file whose header grants no license "
        "(no SPDX-"
        "License-Identifier and no license text such as EPL, Apache, MIT, BSD, GPL, MPL).",
    )
    c.rule(
        "Licensed",
        "A header with an SPDX-License-Identifier or a recognised license grant: /" + LICENSE_GRANT.pattern + "/.",
    )
    c.rule(
        "Code templates",
        "Eclipse code templates (.settings/*.prefs) and EMF .genmodel 'copyrightText' write their "
        "text into every newly generated file; a proprietary clause there is reported as 'code template'.",
    )
    holders, kinds = Counter(), Counter()
    spdx, granted = Counter(), 0
    arr_only = 0
    for f in repo.files:
        t = repo.text(f)
        if t is None:
            continue
        head = header_of(t, f)
        m = SPDX_LIC.search(head)
        if m:
            spdx[m.group(1)] += 1
        full = ext(f) in DOC_EXT or (eclipse and ECLIPSE_FULLTEXT.search(f))
        norm = normalise(t if full else head)
        pm = next((x for x in (r.search(norm) for r in props) if x), None)
        if pm:
            h = holder_name(pm.groupdict().get("holder"))
            kind = (
                "code template"
                if CODE_TEMPLATE.search(f)
                else "documentation"
                if ext(f) in DOC_EXT
                else "Eclipse metadata"
                if full
                else "source header"
            )
            ln = locate(t, pm.group(0))
            starts = line_index(t)
            if c.add(f, ln, snippet(t, starts, ln), kind, match=pm.group(0)):
                holders[h] += 1
                kinds[kind] += 1
            continue
        nhead = normalise(head)
        if LICENSE_GRANT.search(nhead):
            granted += 1
        elif arr.pattern and arr.search(nhead):
            ln = locate(t, arr.search(nhead).group(0))
            if c.add(f, ln, snippet(t, line_index(t), ln), "all rights reserved, no license"):
                arr_only += 1
    total = sum(holders.values())
    # The figure counts exactly what blocks; a missing LICENSE file is the project-basics check's finding.
    c.figure = f"{total + arr_only:,}"
    c.figure_label = "files with a proprietary clause or only 'All rights reserved'"
    c.finding = (
        f"{total:,} files carry a proprietary clause ({kinds['source header']:,} source headers, "
        f"{kinds['Eclipse metadata']} Eclipse metadata files, {kinds['code template']} code templates, "
        f"{kinds['documentation']} documentation files). "
        f"{arr_only:,} further files say 'All rights reserved' without granting any license. "
        f"{granted:,} files grant a license in their header ({sum(spdx.values()):,} with an SPDX identifier)."
    )
    c.tables.append(
        {
            "caption": "Proprietary clause by holder",
            "columns": ["Holder (as written)", "Files"],
            "rows": [[h, n] for h, n in holders.most_common(25)],
        }
    )
    if spdx:
        c.tables.append(
            {
                "caption": "SPDX license identifiers found",
                "columns": ["License", "Files"],
                "rows": [[k, n] for k, n in spdx.most_common()],
            }
        )
    c.status = "blocker" if total or arr_only else "clear"
    ctx.spdx_files = sum(spdx.values())
    ctx.holders = holders
    return c
