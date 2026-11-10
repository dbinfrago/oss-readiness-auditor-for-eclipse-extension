# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import re
from collections import defaultdict

from ..common import RUN_REF, compiled, ext, reverse_dns
from ..infer import own_domains

ID = "namespace"
GROUP = "legal"
TITLE = "Names and namespaces of another organisation"
ICON = "globe"
# Why the check matters for publication
WHY = (
    "Bundle and package names or model namespaces under another organisation's domain claim names – and often a "
    "trademark – that are not yours."
)
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "Confirm the project is hosted by that organisation (setting project.hosted_by), or move bundles, packages and "
    "model namespaces to a domain the project controls (existing models need a migration), or obtain the owner's "
    "agreement."
)


def foundation_names(ctx, c):
    """Own name prefixes under a foundation's name root (org.eclipse, org.polarsys, org.apache, …)."""
    roots = ctx.config.pack_mapping("foundations")
    hosted = set(ctx.config.project["hosted_by"])
    c.rule(
        "Foundation namespaces",
        "An own name prefix "
        + RUN_REF
        + " under a name root that belongs to a foundation ("
        + ", ".join(f"{r}: {n}" for r, n in roots.items())
        + ") claims the foundation's namespace, and often its trademark. Needs judgement unless the project is "
        "hosted there (setting project.hosted_by"
        + (": " + ", ".join(sorted(hosted)) if hosted else ", not set")
        + ").",
    )
    n = 0
    for prefix in ctx.components.own:
        root = next((r for r in roots if prefix == r or prefix.startswith(r + ".")), None)
        if not root or root in hosted:
            continue
        bundles = sorted(
            u
            for u, uid in ctx.components.bsn.items()
            if ctx.components.is_own(u) and (u == prefix or u.startswith(prefix + "."))
        )
        where = next(
            (
                uid + "/META-INF/MANIFEST.MF"
                for name, uid in sorted(ctx.components.bsn.items())
                if name in bundles and uid != "."
            ),
            "(repository root)",
        )
        n += c.add(
            where,
            None,
            f"{prefix} – {roots[root]} namespace ({len(bundles)} bundle(s))",
            "foundation namespace",
            level="judgement",
            match=prefix,
        )
    return n


def run(ctx, c):
    repo = ctx.repo
    names = foundation_names(ctx, c)
    if "emf" not in ctx.config.active_packs:
        c.figure = str(names)
        c.figure_label = "names under a foundation's namespace"
        c.finding = f"{names} own name prefixes lie under a foundation's namespace (model namespaces: pack emf off)."
        c.status = "judgement" if names else "clear"
        return c
    own = own_domains(ctx.components.own)
    allow = compiled(ctx.config.rules["namespace_allow"], "namespace_allow")
    c.rule(
        "Defined namespaces",
        'nsURI="…" attributes in .ecore, .genmodel, .uml, .xcore and .profile.uml files (package definitions).',
    )
    c.rule(
        "Own domains",
        "The repository's own name prefixes " + RUN_REF + ", reversed: org.example.tool -> "
        "example.org/tool. A namespace is the project's own if its host is the domain or a subdomain and, for a "
        "deeper prefix, its path starts with the next name segment.",
    )
    c.rule(
        "Foreign",
        "A namespace with a registered-looking host (a dot and a top-level domain) that is not the "
        "project's own, not reserved for examples (example.com, *.test, …)"
        + (" and matches none of the accepted patterns " + ", ".join(f"/{r.pattern}/" for r in allow) if allow else "")
        + ". Reversed names as host (http://org.example.model) are foreign unless they start with an own prefix. URNs "
        "and hostless URIs (http:///…) are neutral.",
    )
    found = defaultdict(set)
    for f in repo.files:
        if ext(f) not in (".ecore", ".genmodel", ".uml", ".xcore"):
            continue
        t = repo.text(f) or ""
        for m in re.finditer(r'\bnsURI\s*=\s*"([^"]+)"', t):
            found[m.group(1)].add(f)

    def foreign(uri):
        m = re.match(r"(?i)^[a-z][\w+.-]*://([^/:]+)(?::\d+)?(/[^?#]*)?", uri)
        if not m or "." not in m.group(1) or not re.search(r"\.[a-z]{2,}$", m.group(1), re.I):
            return False
        host, path = m.group(1).lower(), (m.group(2) or "/").lower()
        if host.startswith("www."):
            host = host[4:]
        if re.search(r"(^|\.)(example\.(com|org|net)|[\w-]+\.(test|example|invalid|localhost))$", host):
            return False  # reserved for examples (RFC 2606)
        if reverse_dns(host):  # http://org.example.model: a reversed name, judged by the own prefixes
            return not (ctx.components.is_own(host) or any(r.search(uri) for r in allow))
        for d, seg in own:
            if (host == d or host.endswith("." + d)) and (not seg or path.lstrip("/").startswith(seg)):
                return False
        return not any(r.search(uri) for r in allow)

    flagged = {u: fs for u, fs in found.items() if foreign(u)}
    n = 0
    for u, fs in sorted(flagged.items()):
        n += bool(c.add(sorted(fs)[0], None, u, f"{len(fs)} file(s)", where=sorted(fs)))
    c.figure = str(n + names)
    c.figure_label = "names and model namespaces under another organisation's domain"
    c.finding = (
        f"{names} own name prefixes (bundles, Java packages) lie under a foundation's namespace. "
        f"{len(found)} model namespaces are defined in the repository; {n} of them use a domain of another "
        "organisation. Renaming bundles and packages breaks their users; changing a model namespace needs a "
        "migration of existing models."
    )
    c.status = "judgement" if n or names else "clear"
    return c
