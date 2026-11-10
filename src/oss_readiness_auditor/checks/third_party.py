# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
import re
from collections import Counter

from ..common import BINARY_EXT, ext

ID = "third-party"
GROUP = "legal"
TITLE = "Third-party components and licenses"
ICON = "package-search"
# Why the check matters for publication
WHY = "Every bundled component needs a compatible license and must be named in the notices."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "A bill of materials (SBOM) with the license of every bundled component; incompatible components are replaced or "
    "removed, the others named in the NOTICE file."
)

STRONG_COPYLEFT = re.compile(r"(?i)\b(A?GPL|SSPL|BUSL|Commons-Clause|CC-BY-NC|UNLICENSED|SEE LICENSE)\b")


def run(ctx, c):
    repo = ctx.repo
    c.rule(
        "npm licenses",
        "'license' field of every non-dev package in package-lock.json. Blocker: GPL/AGPL/SSPL/BUSL/"
        "non-commercial or UNLICENSED (except the project's own private package). Missing field: needs judgement.",
    )
    c.rule(
        "Maven dependencies",
        "<dependency> entries of the repository's pom.xml files that are not the project's own "
        "group. Their license cannot be determined offline; they are listed for the SBOM.",
    )
    c.rule(
        "Target platforms",
        "Eclipse .target files: <unit> and Maven <dependency> entries per p2/Maven location – "
        "the third-party bundles the product is built from; licenses are listed in the p2 metadata, not checked here.",
    )
    c.rule(
        "Committed jars",
        "Jars tracked in the repository, and jars inside tracked zip archives, are identified from their "
        "MANIFEST.MF (Bundle-SymbolicName, Bundle-Version, Bundle-Name, Bundle-Vendor, Bundle-License; %keys from "
        "the jar's properties), META-INF/maven/**/pom.properties, and – without Bundle-License – the license text in "
        "the jar's about.html or LICENSE/NOTICE file: 'own build' (own name), 'locally built upstream bundle' (someone else's "
        "bundle in a SNAPSHOT or development build – typically a patched copy, whose license may require publishing "
        "its source), 'third-party' or 'unidentified'. Identified versions are checked for known vulnerabilities.",
    )
    c.rule(
        "Committed binaries",
        f"Tracked files with extension {', '.join(sorted(BINARY_EXT))} – their content and "
        "license cannot be reviewed from source (needs judgement).",
    )
    lic = Counter()
    flagged = missing = 0
    for lock, pkgs in ctx.npm_locks.items():
        for name, p in pkgs.items():
            lic_id = p.get("license") or ("(private package)" if p.get("root") else "(missing)")
            if isinstance(lic_id, dict):
                lic_id = lic_id.get("type", "(missing)")
            lic[lic_id] += 1
            if p.get("root"):
                continue
            if STRONG_COPYLEFT.search(str(lic_id)):
                flagged += c.add(
                    lock, None, f"{name}@{p.get('version')}: {lic_id}", "npm license: copyleft / restricted"
                )
            elif lic_id == "(missing)":
                missing += c.add(
                    lock,
                    None,
                    f"{name}@{p.get('version')}: no license in lockfile",
                    "npm license: missing",
                    level="judgement",
                )
    jars = {j["file"] for j in ctx.committed_jars if j["member"] is None}
    binaries = [
        f
        for f in repo.files
        if ext(f) in BINARY_EXT and f not in jars and c.add(f, None, "", "committed binary", level="judgement")
    ]
    jar_rows = []
    for j in ctx.committed_jars:
        i = j["identity"]
        name = i["bsn"] or (i["maven"][0][0] if i["maven"] else os.path.basename(j["member"] or j["file"]))
        version = i["version"] or (i["maven"][0][1] if i["maven"] else "")
        lic_text = i["license"] or "not declared"
        text = (f"in {j['member']}: " if j["member"] else "") + f"{name} {version}".strip()
        text += (f" – {i['name']}" if i["name"] else "") + (f" ({i['vendor']})" if i["vendor"] else "")
        text += f"; license: {lic_text}"
        if j["kind"] == "locally built upstream bundle":
            text += " – a patched or locally built copy of someone else's bundle: its license may require the source"
        if c.add(j["file"], None, text, "committed jar: " + j["kind"], level="judgement"):
            jar_rows.append(
                [j["file"] + (f" › {j['member']}" if j["member"] else ""), name, version, j["kind"], lic_text]
            )
            if j["member"] is None:
                binaries.append(j["file"])
    maven = [
        d
        for d in ctx.maven_deps
        if c.add(
            d["source"],
            d.get("line"),
            f"{d['name']}:{d['version']}",
            "Maven dependency (license not checked)",
            level="judgement",
        )
    ]
    # Eclipse target platforms: the p2 repositories and units the product is built against
    repos, units = Counter(), 0
    if "eclipse" in ctx.config.active_packs:
        for f in repo.files:
            if ext(f) != ".target":
                continue
            t = repo.text(f) or ""
            fu = 0
            for loc in re.finditer(r"<location\b[^>]*>(.*?)</location>", t, re.S):
                body = loc.group(0)
                r = re.search(r'<repository\b[^>]*\blocation="([^"]+)"', body)
                n = len(re.findall(r"<unit\b", body)) + len(re.findall(r"<dependency>", body))
                repos[r.group(1) if r else "(Maven / other location)"] += n
                fu += n
            if fu and c.add(f, None, f"{fu} units", "target platform (licenses not checked)", level="judgement"):
                units += fu
    c.figure = f"{sum(lic.values()) + len(maven) + units:,}"
    c.figure_label = "third-party components declared in the sources"
    c.finding = (
        f"{sum(lic.values())} npm packages in {len(ctx.npm_locks)} lockfile(s): {flagged} with a copyleft or "
        f"restricted license, {missing} without license information in the lockfile. {len(maven)} direct "
        f"Maven dependencies (licenses to be confirmed in an SBOM). "
        + (f"{units} units from {len(repos)} p2/Maven locations in Eclipse target platforms. " if units else "")
        + f"{len(binaries)} committed binary files"
        + (
            f", {len(jar_rows)} jars identified ({sum(1 for r in jar_rows if r[3] == 'locally built upstream bundle')}"
            " locally built copies of upstream bundles)"
            if jar_rows
            else ""
        )
        + ". Components that only appear in a build are checked with "
        "--product."
    )
    if lic:
        c.tables.append(
            {
                "caption": "npm licenses",
                "columns": ["License", "Packages"],
                "rows": [[k, n] for k, n in lic.most_common()],
            }
        )
    if jar_rows:
        c.tables.append(
            {
                "caption": "Committed jars",
                "columns": ["File", "Bundle / artifact", "Version", "Kind", "License"],
                "rows": jar_rows[:60],
            }
        )
    if repos:
        c.tables.append(
            {
                "caption": "Target platform repositories",
                "columns": ["Repository", "Units"],
                "rows": [[k, n] for k, n in repos.most_common(30)],
            }
        )
    c.status = "blocker" if flagged else ("judgement" if maven or missing or binaries or units else "clear")
    return c
