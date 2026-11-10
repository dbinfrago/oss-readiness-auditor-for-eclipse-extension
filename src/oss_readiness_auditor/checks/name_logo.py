# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
import re
from collections import defaultdict

from ..common import DOC_EXT, IMAGE_EXT, RUN_REF, ext, line_index, line_of, snippet

ID = "name-logo"
GROUP = "legal"
TITLE = "Product name and logos (trademark rights)"
ICON = "tag"
# Why the check matters for publication
WHY = (
    "Publishing under a name or with a logo needs the right to use them – the project's own as well as those of "
    "partners and third parties."
)
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "A decision per name and logo: either the owner confirms in writing that the open-source project may use it "
    "(ideally with a trademark policy), or it is renamed or replaced before publication. Partner and third-party "
    "logos need their owner's permission or are removed. The occurrences below show how much a rename would touch."
)

BRANDING_FILE = re.compile(
    r"(?i)(^|/)(about\.(?:ini|properties|mappings|html)|plugin\.properties|bundle\.properties|"
    r"feature\.properties|plugin_customization\.ini|[^/]+\.product|splash\.\w+)$"
)


def branding_images(repo, components):
    """Images an Eclipse product shows as its identity: .product splash/window/about images, the aboutImage and
    windowImages properties of the org.eclipse.core.runtime.products extension, splash.* files."""
    found = {}
    for f in repo.files:
        if re.search(r"(?i)(^|/)splash\.(bmp|png|jpg|gif)$", f):
            found[f] = "splash screen"
        if not (f.endswith(".product") or os.path.basename(f) == "plugin.xml"):
            continue
        t = repo.text(f) or ""
        if f.endswith("plugin.xml") and "org.eclipse.core.runtime.products" not in t:
            continue
        refs = re.findall(r'name="(aboutImage|windowImages)"\s+value="([^"]+)"', t)
        refs += [
            ("window icon", v)
            for v in re.findall(r"<windowImages\b[^>]*>", t)
            for v in re.findall(r'"([^"]+\.\w{3,4})"', v)
        ]
        refs += [("about-dialog image", v) for v in re.findall(r'<aboutInfo>\s*<image\s+path="([^"]+)"', t)]
        base = os.path.dirname(f)
        for kind, value in refs:
            for v in value.split(","):
                v = re.sub(r"^platform:/plugin", "", v.strip())
                cand = []
                m = re.match(r"^/([\w.\-]+)/(.+)$", v)  # /<bundle-id>/<path in the bundle>
                if m and components and m.group(1) in components.bsn:
                    d = components.bsn[m.group(1)]
                    cand = [(d + "/" if d != "." else "") + m.group(2)]
                cand.append((base + "/" if base else "") + v.lstrip("/"))  # relative to the declaring bundle
                for x in [x for x in cand if x in repo.files][:1]:
                    found.setdefault(
                        x, {"aboutImage": "about-dialog image", "windowImages": "window icon"}.get(kind, kind)
                    )
    return found


def run(ctx, c):
    repo = ctx.repo
    pats = ctx.config.project["name_patterns"] or []
    eclipse = "eclipse" in ctx.config.active_packs
    c.rule(
        "Logos",
        "Image files whose name contains 'logo'"
        + (
            "; images an Eclipse product shows as its identity (splash screen, about-dialog image, window icons – from "
            ".product files and the org.eclipse.core.runtime.products extension)"
            if eclipse
            else ""
        )
        + ".",
    )
    if pats:
        c.rule(
            "Product name",
            "Occurrences of the product name patterns in text files (case-sensitive). The patterns "
            "are not built into the tool: they are inferred from the name of .product files and the root POM, or "
            "configured for the run "
            + RUN_REF
            + "."
            + (
                " Occurrences in product branding files (about.*, *.product, plugin/feature/bundle.properties, "
                "plugin_customization.ini) are what users see as the product's identity."
                if eclipse
                else ""
            ),
        )
    else:
        c.rule(
            "Product name",
            "No product name configured, and none found in .product files or the root POM: only "
            "logo files are reported. Set project.name_patterns in the configuration.",
        )
    rx = re.compile("|".join(f"(?:{p})" for p in pats)) if pats else None
    images = {
        f: "file named 'logo'" for f in repo.files if ext(f) in IMAGE_EXT and "logo" in os.path.basename(f).lower()
    }
    if eclipse:
        for f, kind in branding_images(repo, ctx.components).items():
            images.setdefault(f, kind)
    shown = [[f, kind] for f, kind in sorted(images.items()) if c.add(f, None, kind, "logo / branding image")]
    where = defaultdict(lambda: [0, 0])
    for f in repo.files if rx else ():
        t = repo.text(f)
        if not t:
            continue
        ms = list(rx.finditer(t))
        if ms:
            kind = (
                "product branding"
                if eclipse and BRANDING_FILE.search(f)
                else "documentation"
                if ext(f) in DOC_EXT
                else "code, models and configuration"
            )
            starts = line_index(t)
            ln = line_of(starts, ms[0].start())
            if c.add(f, ln, snippet(t, starts, ln), "name: " + kind):
                where[kind][0] += 1
                where[kind][1] += len(ms)
    files, occ = sum(v[0] for v in where.values()), sum(v[1] for v in where.values())
    c.figure = str(len(shown))
    c.figure_label = "logo and branding images" + (f" · name in {files:,} files" if rx else "")
    c.finding = f"{len(shown)} logo and branding images to clear; " + (
        f"the product name appears {occ:,} times in {files:,} files ({where['product branding'][0]} of them product "
        "branding that users see)."
        if rx
        else "no product name pattern available."
    )
    if shown:
        c.tables.append(
            {
                "caption": "Logo and branding images – one decision each",
                "columns": ["Image", "Found as"],
                "rows": shown[:40],
            }
        )
    if where:
        c.tables.append(
            {
                "caption": "Where the product name appears",
                "columns": ["Kind of file", "Files", "Occurrences"],
                "rows": [[k, v[0], v[1]] for k, v in sorted(where.items(), key=lambda x: (-x[1][0], x[0]))],
            }
        )
    c.status = "judgement" if shown or occ else "clear"
    return c
