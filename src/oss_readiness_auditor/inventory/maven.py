# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Maven dependencies declared in pom.xml files."""

import os
import re
import xml.etree.ElementTree as ET

from ..common import line_index, line_of


def maven_deps(repo):
    own_groups, deps = set(), []
    poms = [f for f in repo.files if os.path.basename(f) == "pom.xml"]
    parsed = {}
    for f in poms:
        try:
            root = ET.fromstring((repo.text(f) or "").encode("utf-8"))
        except ET.ParseError:
            continue
        ns = {"m": root.tag[1:].split("}")[0]} if root.tag.startswith("{") else {"m": ""}
        q = (lambda p: "m:" + p) if ns["m"] else (lambda p: p)
        g = root.findtext(q("groupId"), namespaces=ns) or root.findtext(q("parent") + "/" + q("groupId"), namespaces=ns)
        if g:
            own_groups.add(g.strip())
        parsed[f] = (root, ns, q)
    for f, (root, ns, q) in parsed.items():
        props = {}
        pe = root.find(q("properties"), namespaces=ns)
        if pe is not None:
            for e in pe:
                props[e.tag.split("}")[-1]] = (e.text or "").strip()
        text = repo.text(f) or ""
        starts = line_index(text)
        for d in root.iter(f"{{{ns['m']}}}dependency" if ns["m"] else "dependency"):
            g = d.findtext(q("groupId"), namespaces=ns)
            a = d.findtext(q("artifactId"), namespaces=ns)
            v = d.findtext(q("version"), namespaces=ns)
            scope = d.findtext(q("scope"), namespaces=ns)
            if not g or not a or not v or (scope or "").strip() == "test":
                continue
            g, a, v = g.strip(), a.strip(), v.strip()
            v = re.sub(r"\$\{([^}]+)\}", lambda m, props=props: props.get(m.group(1), m.group(0)), v)
            if g in own_groups or "${" in v or g.startswith("org.eclipse.tycho"):
                continue
            pos = text.find("<artifactId>" + a)
            deps.append(
                {"name": f"{g}:{a}", "version": v, "source": f, "line": line_of(starts, pos) if pos >= 0 else None}
            )
    return deps
