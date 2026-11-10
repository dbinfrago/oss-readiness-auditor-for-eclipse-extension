# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Offline matching against OSV vulnerability dumps."""

import hashlib
import json
import os
import re
import zipfile
from collections import defaultdict

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNRATED"]

MAVEN_QUALIFIERS = {
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    "rc": 4,
    "cr": 4,
    "snapshot": 5,
    "": 6,
    "ga": 6,
    "final": 6,
    "release": 6,
    "sp": 7,
}


def maven_key(v):
    """Simplified Maven ComparableVersion: numbers numerically, known qualifiers ranked, other text after them."""
    items = []
    for tok in re.findall(r"\d+|[A-Za-z]+", v.lower()):
        if tok.isdigit():
            items.append((2, int(tok), ""))
        else:
            r = MAVEN_QUALIFIERS.get(tok)
            items.append((1, r, "") if r is not None else (1, 8, tok))
    while items and items[-1] in ((2, 0, ""), (1, 6, "")):
        items.pop()
    return items


def semver_key(v):
    m = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?", v or "")
    if not m:
        return ((0, 0, 0), (0,))
    core = tuple(int(x or 0) for x in m.group(1, 2, 3))
    pre = m.group(4)
    if not pre:
        return (core, (1,))
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (core, (0,) + ids)


def vkey(eco, v):
    return maven_key(v) if eco == "Maven" else semver_key(v)


def cmp_key(a, b):
    """Compare Maven item lists of different lengths (missing items act like the 'release' item)."""
    if isinstance(a, list):
        n = max(len(a), len(b))
        pad = (1, 6, "")
        for i in range(n):
            x = a[i] if i < len(a) else pad
            y = b[i] if i < len(b) else pad
            if x != y:
                # numbers rank above qualifiers
                return -1 if x < y else 1
        return 0
    return -1 if a < b else (1 if a > b else 0)


def in_ranges(eco, version, ranges):
    vk = vkey(eco, version)
    for r in ranges:
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        affected = False
        for ev in r.get("events", []):
            if "introduced" in ev:
                intro = ev["introduced"]
                if intro == "0" or cmp_key(vk, vkey(eco, intro)) >= 0:
                    affected = True
            elif "fixed" in ev:
                if affected and cmp_key(vk, vkey(eco, ev["fixed"])) < 0:
                    return True
                affected = False if cmp_key(vk, vkey(eco, ev["fixed"])) >= 0 else affected
            elif "last_affected" in ev:
                if affected and cmp_key(vk, vkey(eco, ev["last_affected"])) <= 0:
                    return True
                affected = False
            elif "limit" in ev:
                if affected and cmp_key(vk, vkey(eco, ev["limit"])) < 0:
                    return True
                affected = False
        if affected:
            return True
    return False


class OsvDb:
    def __init__(self, paths, wanted):
        self.index = defaultdict(list)
        self.info = []
        names = defaultdict(set)
        for e, n in wanted:
            names[e].add(n)
        for p in paths:
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            z = zipfile.ZipFile(p)
            count, newest = 0, ""
            for entry in z.namelist():
                if not entry.endswith(".json"):
                    continue
                raw = z.read(entry)
                try:
                    d = json.loads(raw)
                except ValueError:
                    continue
                count += 1
                newest = max(newest, d.get("modified", ""))
                if d.get("withdrawn"):
                    continue
                for a in d.get("affected", []):
                    pk = a.get("package", {})
                    e, n = pk.get("ecosystem"), pk.get("name")
                    if e in names and n in names[e]:
                        self.index[(e, n)].append((d, a))
            self.info.append(
                {"file": os.path.basename(p), "sha256": h.hexdigest(), "advisories": count, "newest_entry": newest}
            )

    @staticmethod
    def severity(d, a):
        for src in (d.get("database_specific"), a.get("database_specific"), a.get("ecosystem_specific")):
            s = (src or {}).get("severity")
            if isinstance(s, str) and s:
                s = s.upper()
                return "MEDIUM" if s == "MODERATE" else (s if s in SEVERITY_ORDER else "UNRATED")
        return "UNRATED"

    def match(self, eco, name, version):
        out = []
        for d, a in self.index.get((eco, name), []):
            if version in a.get("versions", []) or in_ranges(eco, version, a.get("ranges", [])):
                fixed = sorted(
                    {ev["fixed"] for r in a.get("ranges", []) for ev in r.get("events", []) if "fixed" in ev}
                )
                out.append(
                    {
                        "id": d["id"],
                        "aliases": d.get("aliases", []),
                        "summary": (d.get("summary") or "")[:160],
                        "severity": self.severity(d, a),
                        "fixed": fixed,
                    }
                )
        return out
