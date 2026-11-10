# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Jars of built products, and OSGi bundle names mapped to Maven coordinates."""

import io
import os
import re
import zipfile
from collections import defaultdict


def osgi_version(v):
    m = re.match(r"(\d+(?:\.\d+){0,2})", v or "")
    return m.group(1) if m else v


def product_components(products, own_prefixes, bundle_to_maven=None):
    """(eco, name, version) -> sources, for all jars (also nested) in the product folders.
    bundle_to_maven: Bundle-SymbolicName -> Maven coordinates, for jars without Maven metadata."""
    comps = defaultdict(set)
    b2m = bundle_to_maven or {}

    def manifest(z):
        try:
            raw = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
        except KeyError:
            return {}
        raw = re.sub(r"\r?\n ", "", raw)
        return dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)

    def walk(z, label, depth=0):
        found = False
        for n in z.namelist():
            if n.startswith("META-INF/maven/") and n.endswith("pom.properties"):
                p = dict(
                    line.split("=", 1)
                    for line in z.read(n).decode("utf-8", "replace").splitlines()
                    if "=" in line and not line.startswith("#")
                )
                if p.get("groupId") and p.get("artifactId") and p.get("version"):
                    g = p["groupId"].strip()
                    if not g.startswith(own_prefixes):
                        comps[("Maven", g + ":" + p["artifactId"].strip(), p["version"].strip())].add(label)
                    found = True
        if depth < 3:
            for n in z.namelist():
                if n.endswith(".jar"):
                    try:
                        walk(zipfile.ZipFile(io.BytesIO(z.read(n))), label, depth + 1)
                    except (zipfile.BadZipFile, KeyError):
                        pass
        if not found:
            m = manifest(z)
            bsn = m.get("Bundle-SymbolicName", "").split(";")[0].strip()
            if bsn in b2m:
                comps[("Maven", b2m[bsn], osgi_version(m.get("Bundle-Version", "").strip()))].add(label)

    for d in products:
        label = f"product:{os.path.basename(os.path.normpath(d)) or d}"
        for root, _, files in os.walk(d, followlinks=True):
            for f in files:
                if f.endswith(".jar"):
                    # plugins/<bundle>_<version>[.jar|/…]: jars inside a project bundle are attributed to it
                    rel = os.path.relpath(os.path.join(root, f), d).replace(os.sep, "/").split("/")
                    bsn = rel[1].split("_")[0] if len(rel) > 1 and rel[0] == "plugins" else ""
                    if bsn.endswith(".jar"):
                        bsn = bsn[:-4]
                    lab = f"{label}:{bsn}" if bsn.startswith(own_prefixes) and own_prefixes else label
                    try:
                        walk(zipfile.ZipFile(os.path.join(root, f)), lab)
                    except (zipfile.BadZipFile, OSError):
                        pass
    return comps


# License texts recognised in a jar's about.html / LICENSE when the manifest declares none
JAR_LICENSES = [
    ("EPL-2.0", r"Eclipse Public License[^.<]{0,40}(?:v(?:ersion)?\s*)?2\.0|epl-2\.0|EPL-2\.0"),
    ("EPL-1.0", r"Eclipse Public License[^.<]{0,40}(?:v(?:ersion)?\s*)?1\.0|epl-v10"),
    ("Apache-2.0", r"Apache License,?\s+Version 2\.0"),
    ("MIT", r"Permission is hereby granted, free of charge"),
    ("BSD", r"Redistribution and use in source and binary forms"),
    ("LGPL", r"GNU Lesser General Public License"),
    ("GPL", r"GNU General Public License"),
]


def jar_license(z, names):
    for n in names:
        if re.search(r"(?i)^(about\.html?|(META-INF/)?(LICEN[CS]E|NOTICE)[^/]*)$", n):
            t = z.read(n).decode("utf-8", "replace")
            # REUSE-IgnoreStart (a pattern, not this file's license)
            m = re.search(r"SPDX-License-Identifier:\s*([^\s<>\"]+)", t)
            # REUSE-IgnoreEnd
            if m:
                return f"{m.group(1)} (from {n})"
            hit = next((spdx for spdx, rx in JAR_LICENSES if re.search(rx, t, re.I)), None)
            if hit:
                return f"{hit} (from {n})"
    return ""


def jar_properties(z, manifest):
    """Default (non-localised) properties of a jar, for %key values of its manifest."""
    base = manifest.get("Bundle-Localization", "OSGI-INF/l10n/bundle")
    props = {}
    for n in (base + ".properties", "plugin.properties", "bundle.properties"):
        try:
            text = z.read(n).decode("latin-1")
        except KeyError:
            continue
        for m in re.finditer(r"(?m)^[ \t]*([\w.\-]+)[ \t]*[=:][ \t]*(.*)$", text):
            props.setdefault(m.group(1), m.group(2).strip())
    return props


def jar_identity(z):
    """What a jar says about itself: OSGi manifest headers and Maven coordinates (META-INF/maven/**/pom.properties)."""
    try:
        raw = re.sub(r"\r?\n ", "", z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace"))
        m = {k.strip(): v.strip() for k, v in (line.split(":", 1) for line in raw.splitlines() if ":" in line)}
    except KeyError:
        m = {}
    maven = []
    for n in z.namelist():
        if n.startswith("META-INF/maven/") and n.endswith("pom.properties"):
            p = dict(
                line.split("=", 1)
                for line in z.read(n).decode("utf-8", "replace").splitlines()
                if "=" in line and not line.startswith("#")
            )
            if p.get("groupId") and p.get("artifactId") and p.get("version"):
                maven.append((p["groupId"].strip() + ":" + p["artifactId"].strip(), p["version"].strip()))
    props = jar_properties(z, m)

    def res(v):
        return props.get(v[1:], v) if v.startswith("%") else v

    names = z.namelist()
    return {
        "bsn": m.get("Bundle-SymbolicName", "").split(";")[0].strip(),
        "version": m.get("Bundle-Version") or m.get("Implementation-Version") or "",
        "name": res(m.get("Bundle-Name") or m.get("Implementation-Title") or ""),
        "vendor": res(m.get("Bundle-Vendor") or m.get("Implementation-Vendor") or ""),
        "license": m.get("Bundle-License", "") or jar_license(z, names),
        "maven": maven,
    }


def committed_jars(repo, is_own, bundle_to_maven=None):
    """Jars tracked in the repository, and jars inside tracked zip archives: [{file, member, identity, kind,
    components}]. kind: 'own build', 'locally built upstream bundle' (a SNAPSHOT or development build of someone
    else's bundle – often a patched copy), 'third-party' or 'unidentified'. components: (eco, name, version) for
    vulnerability matching."""
    b2m = bundle_to_maven or {}
    out = []

    def add(file, member, z):
        ident = jar_identity(z)
        name = ident["bsn"] or (ident["maven"][0][0] if ident["maven"] else "")
        local = re.search(r"SNAPSHOT|qualifier", f"{member or file} {ident['version']}", re.I)
        if not name:
            kind = "unidentified"
        elif is_own(name) or any(is_own(ga.split(":")[0]) for ga, _ in ident["maven"]):
            kind = "own build"
        else:
            kind = "locally built upstream bundle" if local else "third-party"
        comps = [("Maven", ga, v) for ga, v in ident["maven"]] if kind != "own build" else []
        if not comps and ident["bsn"] in b2m and kind != "own build":
            comps = [("Maven", b2m[ident["bsn"]], osgi_version(ident["version"]))]
        out.append({"file": file, "member": member, "identity": ident, "kind": kind, "components": comps})

    for f in repo.files:
        if not f.lower().endswith((".jar", ".zip")):
            continue
        try:
            z = zipfile.ZipFile(repo.path(f))
        except (zipfile.BadZipFile, OSError):
            continue
        with z:
            if f.lower().endswith(".jar"):
                add(f, None, z)
                continue
            for n in z.namelist():
                if n.lower().endswith(".jar"):
                    try:
                        add(f, n, zipfile.ZipFile(io.BytesIO(z.read(n))))
                    except (zipfile.BadZipFile, KeyError):
                        pass
    return out
