# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
import re
from collections import Counter

from ..headers import nls_resolver

ID = "eclipse-metadata"
GROUP = "legal"
TITLE = "Eclipse vendor and license metadata"
ICON = "package-search"
# Why the check matters for publication
WHY = "Eclipse shows vendor, copyright and license of every installed feature and bundle to the user."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "Name the publishing organisation or project as vendor, give every feature a license and every bundle an "
    "about.html."
)


def run(ctx, c):
    """Eclipse pack only: who the bundles and features name as vendor, and whether they carry license metadata."""
    repo = ctx.repo
    if "eclipse" not in ctx.config.active_packs:
        return None
    vendors_ok = [v.lower() for v in ctx.config.project["vendors"]]
    c.rule(
        "Vendors",
        "Bundle-Vendor (MANIFEST.MF) and provider-name (feature.xml), %keys resolved from "
        "the Bundle-Localization file (default OSGI-INF/l10n/bundle.properties), plugin.properties and "
        "feature.properties. Vendors other than the accepted "
        "ones (project.vendors: " + (", ".join(ctx.config.project["vendors"]) or "none configured") + ") are listed.",
    )
    c.rule(
        "Feature license",
        "feature.xml without a <license> element, or with an empty one: the update manager shows "
        "no license to the user.",
    )
    c.rule(
        "about.html",
        "Bundles without an about.html (the Eclipse convention for the license of a plug-in; required "
        "by the Eclipse Foundation, recommended elsewhere).",
    )
    vendors, kinds = Counter(), Counter()
    bundles = 0
    for f in repo.files:
        if f.endswith("META-INF/MANIFEST.MF"):
            folder = os.path.dirname(os.path.dirname(f)) or "."
            t = re.sub(r"\r?\n ", "", repo.text(f) or "")
            if not re.search(r"(?m)^Bundle-SymbolicName:", t):
                continue
            bundles += 1
            loc = re.search(r"(?m)^Bundle-Localization:\s*(\S+)", t)
            res = nls_resolver(
                repo,
                folder,
                [
                    (loc.group(1) if loc else "OSGI-INF/l10n/bundle") + ".properties",
                    "plugin.properties",
                    "bundle.properties",
                ],
            )
            m = re.search(r"(?m)^Bundle-Vendor:\s*(.+?)\s*$", t)
            v = res(m.group(1)) if m else ""
            if v and v.lower() not in vendors_ok:
                if c.add(f, None, v, "bundle vendor", level="judgement", match=v):
                    vendors[v] += 1
                    kinds["vendor"] += 1
            prefix = "" if folder == "." else folder + "/"
            if prefix + "about.html" not in repo.files and prefix + "about.htm" not in repo.files:
                if c.add(f, None, "no about.html", "about.html missing", level="judgement"):
                    kinds["about.html missing"] += 1
        elif os.path.basename(f) == "feature.xml":
            t = repo.text(f) or ""
            folder = os.path.dirname(f) or "."
            res = nls_resolver(repo, folder, ["feature.properties"])
            m = re.search(r'<feature\b[^>]*?\bprovider-name="([^"]*)"', t)
            v = res(m.group(1)) if m else ""
            if v and v.lower() not in vendors_ok:
                if c.add(f, None, v, "feature provider", level="judgement", match=v):
                    vendors[v] += 1
                    kinds["vendor"] += 1
            lm = re.search(r"<license\b([^>]*)>(.*?)</license>|<license\b[^>]*/>", t, re.S)
            text = res((lm.group(2) or "").strip()) if lm and lm.group(2) is not None else ""
            url = re.search(r'\burl="([^"]*)"', lm.group(1) or "") if lm and lm.group(1) else None
            if not lm or (not text.strip() and not (url and url.group(1).strip())):
                if c.add(f, None, "no license in feature.xml", "feature without license", level="judgement"):
                    kinds["feature without license"] += 1
    n = sum(kinds.values())
    c.figure = str(len(vendors))
    c.figure_label = "vendor names to confirm" if vendors else "vendor names to confirm (none)"
    c.finding = (
        f"{bundles} bundles. {kinds['vendor']} bundles/features name a vendor that is not configured as "
        f"accepted; {kinds['feature without license']} features carry no license; "
        f"{kinds['about.html missing']} bundles have no about.html."
    )
    if vendors:
        c.tables.append(
            {
                "caption": "Vendor names",
                "columns": ["Vendor (resolved)", "Bundles/features"],
                "rows": [[k, v] for k, v in vendors.most_common(25)],
            }
        )
    c.status = "judgement" if n else "clear"
    return c
