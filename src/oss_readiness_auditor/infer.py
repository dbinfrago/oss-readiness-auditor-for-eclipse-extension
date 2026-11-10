# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Inference of project facts from the repository (shown in the report; override with --config)."""

import re
from collections import Counter, defaultdict


def common_prefix(names):
    segs = [n.split(".") for n in names]
    out = []
    for parts in zip(*segs, strict=False):
        if len(set(parts)) != 1:
            break
        out.append(parts[0])
    return ".".join(out)


# Organisation roots shared by many independent projects: an own prefix needs at least one more segment.
UMBRELLA_ROOTS = {
    "org.eclipse",
    "org.polarsys",
    "org.apache",
    "org.osgi",
    "com.github",
    "io.github",
    "com.gitlab",
    "io.gitlab",
    "net.sourceforge",
    "org.github",
    "org.codehaus",
    "com.googlecode",
    "org.ow2",
    "io.jenkins",
}


def infer_own_prefixes(names, min_share=0.9):
    """Own name prefixes from the Bundle-SymbolicNames (and Maven groupIds) of the repository. Names are grouped by
    their organisation root (first two segments, e.g. org.eclipse or fr.example); within a group the deepest prefix
    shared by at least `min_share` of the names is the project's prefix (org.eclipse.papyrus, not org.eclipse).
    Names outside it are grouped again one segment deeper. A group with under 5 % of the names (in repositories with
    20+ names) contributes its exact names only, not a prefix. Under roots shared by many projects (UMBRELLA_ROOTS, e.g.
    org.eclipse, org.polarsys) grouping starts one segment deeper."""

    def deepest(group, depth):
        # longest prefix (>= depth segments) covering min_share of the group
        cnt = Counter()
        for n in group:
            parts = n.split(".")
            for k in range(depth, len(parts) + 1):
                cnt[".".join(parts[:k])] += 1
        cands = [p for p, c in cnt.items() if c >= min_share * len(group)]
        if not cands:
            return None, group
        best = max(cands, key=lambda p: (p.count("."), cnt[p]))
        return best, [n for n in group if not (n == best or n.startswith(best + "."))]

    names = sorted({n for n in names if n and "." in n})
    out = []
    umbrella = [n for n in names if ".".join(n.split(".")[:2]) in UMBRELLA_ROOTS and n.count(".") >= 2]
    todo = [(sorted(set(names) - set(umbrella)), 2), (umbrella, 3)]
    while todo:
        group, depth = todo.pop()
        roots = defaultdict(list)
        for n in group:
            roots[".".join(n.split(".")[:depth])].append(n)
        for root, members in sorted(roots.items()):
            if root.count(".") + 1 < depth:  # name shorter than the grouping depth
                out.append(root)
                continue
            if len(names) >= 20 and len(members) < 0.05 * len(names):
                out += members  # a few bundles of another namespace (e.g. fragments of a platform
                continue  # bundle): only these exact names are the project's own
            p, rest = deepest(members, depth)
            if p:
                out.append(p)
            if rest and depth < 4:
                todo.append((rest, depth + 1))
            elif rest:
                out += [common_prefix([n]) for n in rest]
    # drop prefixes covered by a shorter one
    out = sorted(set(out), key=len)
    return [p for i, p in enumerate(out) if not any(p.startswith(q + ".") for q in out[:i])]


# Words of vendor/bundle names that name a host organisation or platform, not the product
NOT_A_PRODUCT = re.compile(r"(?i)eclipse|polarsys|apache|oracle|osgi|example|\.org\b|\.com\b|%")


def bundle_names(repo):
    """Fallback for repositories without a .product file or root POM name (e.g. a single plug-in): the acronym that
    starts the Bundle-Name or Bundle-Vendor ('XYZ Diagram Tools' -> 'XYZ') of more than half of the bundles. %keys
    are resolved from the bundle's localisation file."""
    from .headers import nls_resolver

    acronyms, bundles = Counter(), 0
    for f in repo.files:
        if not f.endswith("META-INF/MANIFEST.MF"):
            continue
        t = re.sub(r"\r?\n ", "", repo.text(f, include_self=True) or "")
        loc = re.search(r"(?m)^Bundle-Localization:\s*(\S+)", t)
        folder = f[: -len("/META-INF/MANIFEST.MF")] if "/" in f[: -len("META-INF/MANIFEST.MF")] else "."
        res = nls_resolver(
            repo,
            folder,
            [
                (loc.group(1) if loc else "OSGI-INF/l10n/bundle") + ".properties",
                "plugin.properties",
                "bundle.properties",
            ],
        )
        bundles += 1
        found = set()
        for header in ("Bundle-Name", "Bundle-Vendor"):
            m = re.search(rf"(?m)^{header}:\s*(.+?)\s*$", t)
            value = res(m.group(1)) if m else ""
            first = value.split()[0] if value.split() else ""
            if not NOT_A_PRODUCT.search(value) and re.fullmatch(r"[A-Z][A-Z0-9]{1,9}", first):
                found.add(first)
        acronyms.update(found)
    # the name of one bundle among many is not the product's name: only acronyms carried by most bundles
    return sorted(a for a, n in acronyms.items() if n > bundles / 2)


def infer_name_patterns(repo):
    """Product names from Eclipse .product files and the root POM <name>; an all-caps first word of a longer name
    (an acronym such as 'XYZ Server' -> 'XYZ') is added. Without either, acronyms from Bundle-Name/Bundle-Vendor
    (bundle_names). Returns (patterns, names)."""
    names = []
    for f in repo.files:
        if f.endswith(".product"):
            m = re.search(r'<product\b[^>]*?\bname="([^"%$]+)"', repo.text(f, include_self=True) or "")
            if m:
                names.append(m.group(1).strip())
    if "pom.xml" in repo.files:
        body = re.sub(
            r"(?s)<parent>.*?</parent>|<!--.*?-->|<build>.*?</build>|<modules>.*?</modules>|"
            r"<dependencies>.*?</dependencies>|<profiles>.*?</profiles>|<developers>.*?</developers>|"
            r"<organization>.*?</organization>",
            "",
            repo.text("pom.xml", include_self=True) or "",
        )
        m = re.search(r"<name>\s*([^<$]+?)\s*</name>", body)
        if m:
            names.append(m.group(1))
    if not names:
        names = bundle_names(repo)
    words = set()
    for n in names:
        if len(n) < 3 and not n.isupper():
            continue
        words.add(n)
        first = n.split()[0]
        if len(n.split()) > 1 and re.fullmatch(r"[A-Z][A-Z0-9]{1,9}", first):
            words.add(first)
    # generic words would match everywhere
    words = {
        w
        for w in words
        if w.lower()
        not in {
            "eclipse",
            "parent",
            "root",
            "main",
            "product",
            "application",
            "app",
            "platform",
            "server",
            "client",
            "tools",
            "core",
        }
    }
    if not words:
        return [], names
    alt = "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in sorted(words, key=lambda w: (-len(w), w)))
    return [r"(?<![.\w])(?:" + alt + r")(?![.\w])"], names


def own_domains(prefixes):
    """Reverse-DNS prefixes -> (domain, first path segment or ''): org.eclipse.papyrus -> ('eclipse.org', 'papyrus')."""
    out = []
    for p in prefixes:
        parts = p.split(".")
        if len(parts) >= 2:
            out.append((parts[1].lower() + "." + parts[0].lower(), parts[2].lower() if len(parts) > 2 else ""))
    return out
