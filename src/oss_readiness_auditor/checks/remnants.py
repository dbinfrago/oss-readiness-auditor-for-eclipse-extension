# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
import re
from collections import Counter

from ..common import RUN_REF, ext, line_index, line_of
from ..headers import manifest_entries

ID = "remnants"
GROUP = "legal"
TITLE = "References to missing components"
ICON = "puzzle"
# Why the check matters for publication
WHY = "The public code must build and run without parts that were removed."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = "Restore the missing parts, remove the references, or confirm that the build generates them."

CLASS_ATTR = re.compile(
    r'\b(?:class|defaultHandler|contributorClass|handler|launcher|delegate)\s*=\s*"([a-zA-Z_][\w.$]*)(?:[:"])'
)


def run(ctx, c):
    repo = ctx.repo
    c.rule(
        "Own names",
        "A name is the project's own if it starts with one of the repository's own name prefixes. "
        "They are not built into the tool: they are inferred from the repository's bundle names or configured "
        "for the run " + RUN_REF + ".",
    )
    c.rule(
        "Missing classes",
        "plugin.xml/fragment.xml attributes class/defaultHandler/contributorClass/handler/launcher/"
        "delegate naming a class with an own name or in a package of the repository, without a .java/.xtend/.kt/"
        ".groovy/.scala source of that class in the repository. Names following EMF/Xtext generator conventions "
        "are tagged 'maybe generated'.",
    )
    c.rule(
        "Missing bundles and features",
        "Own names in Require-Bundle, Fragment-Host, feature.xml <plugin>/<includes>/"
        "<import>, and .product <plugin>/<feature> entries, without a bundle or feature of that name in the repository "
        "(X.source is accepted when X exists: Tycho generates it).",
    )
    c.rule(
        "Missing packages",
        "Own packages in Import-Package (not resolution:=optional) that no bundle of the repository exports.",
    )
    c.rule("Missing modules", "<module> entries in pom.xml whose folder does not exist.")
    classes, packages, bundles, features, exported = set(), set(), set(), set(), set()
    for f in repo.files:
        if ext(f) in (".java", ".xtend", ".kt", ".groovy", ".scala"):
            t = repo.text(f) or ""
            m = re.search(r"(?m)^\s*package\s+([\w.]+)", t)
            if m:
                packages.add(m.group(1))
                classes.add(m.group(1) + "." + os.path.splitext(os.path.basename(f))[0])
        elif f.endswith("META-INF/MANIFEST.MF"):
            t = repo.text(f, include_self=True) or ""
            m = re.search(r"(?m)^Bundle-SymbolicName:\s*([\w.\-]+)", t)
            if m:
                bundles.add(m.group(1))
            exported |= {p for p, _ in manifest_entries(t, "Export-Package")}
        elif os.path.basename(f) == "feature.xml":
            m = re.search(r'<feature\b[^>]*?\bid="([^"]+)"', repo.text(f, include_self=True) or "")
            if m:
                features.add(m.group(1))
    is_own = ctx.components.is_own
    generated_hint = re.compile(
        r"\.(Abstract\w+|\w+(RuntimeModule|StandaloneSetup|Activator|ExecutableExtensionFactory|"
        r"Factory|FactoryImpl|Package|PackageImpl|Switch|AdapterFactory|Validator|ItemProvider\w*|"
        r"Impl|Ide|Setup|Module))$"
    )
    kinds = Counter()

    def report(f, ln, name, tag):
        if c.add(f, ln, name, tag):
            kinds[tag] += 1

    for f in repo.files:
        base = os.path.basename(f)
        if base in ("plugin.xml", "fragment.xml"):
            t = repo.text(f) or ""
            starts = line_index(t)
            for m in CLASS_ATTR.finditer(t):
                fq = m.group(1).split("$")[0]
                if "." not in fq or fq in classes:
                    continue
                if is_own(fq) or fq.rsplit(".", 1)[0] in packages:
                    report(
                        f,
                        line_of(starts, m.start()),
                        fq,
                        "missing class (maybe generated)" if generated_hint.search(fq) else "missing class",
                    )
        elif f.endswith("META-INF/MANIFEST.MF"):
            t = repo.text(f) or ""
            for b, _ in manifest_entries(t, "Require-Bundle") + manifest_entries(t, "Fragment-Host"):
                if is_own(b) and b not in bundles:
                    report(f, None, b, "missing bundle")
            for p, attrs in manifest_entries(t, "Import-Package"):
                if is_own(p) and p not in exported and "optional" not in attrs:
                    report(f, None, p, "missing package")
        elif base == "feature.xml" or f.endswith(".product"):
            t = repo.text(f) or ""
            starts = line_index(t)
            for m in re.finditer(r"<(plugin|includes|feature|import)\b([^>]*)>", t):
                attrs = dict(re.findall(r'\b(id|plugin|feature)="([\w.\-]+)"', m.group(2)))
                kind = "feature" if m.group(1) in ("includes", "feature") or "feature" in attrs else "bundle"
                name = attrs.get("id") or attrs.get("plugin") or attrs.get("feature")
                if m.group(1) == "feature" and base == "feature.xml":
                    continue  # the feature's own id
                if name and is_own(name) and name not in (features if kind == "feature" else bundles):
                    if name.endswith(".source") and name[:-7] in features | bundles:
                        continue  # generated by the Tycho source plug-in from an existing feature/bundle
                    report(f, line_of(starts, m.start()), name, "missing " + kind)
        elif base == "pom.xml":
            t = repo.text(f) or ""
            starts = line_index(t)
            for m in re.finditer(r"<module>\s*([^<\s]+)\s*</module>", t):
                d = os.path.normpath(os.path.join(os.path.dirname(f), m.group(1)))
                if not os.path.isdir(repo.path(d)):
                    report(f, line_of(starts, m.start()), m.group(1), "missing module")
    n = sum(kinds.values())
    c.figure = f"{n}"
    c.figure_label = "references to components that are not in the repository"
    c.finding = (
        (
            "References to classes, bundles, packages or modules that do not exist in the repository – typically "
            "left over from removed components, or produced only by code generation during the build. "
            + ", ".join(f"{k}: {v}" for k, v in kinds.most_common())
            + "."
        )
        if n
        else "No dangling references found."
    )
    c.status = "judgement" if n else "clear"
    return c
