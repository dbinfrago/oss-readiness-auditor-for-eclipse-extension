# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Units (bundles, modules), families and their internal dependency graph."""

import fnmatch
import os
import re
from collections import Counter, defaultdict

from .infer import infer_own_prefixes

DESCRIPTORS = {
    "pom.xml": "maven",
    "feature.xml": "feature",
    "package.json": "npm",
    "pyproject.toml": "python",
    "setup.py": "python",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
}

KIND_RANK = ["bundle", "feature", "npm", "python", "go", "rust", "gradle", "maven", "aggregator"]

PACKAGING_ONLY = {
    "eclipse-feature",
    "eclipse-repository",
    "eclipse-target-definition",
    "eclipse-update-site",
    "eclipse-application",
}

BUILD_FAMILY = "(repository, build & packaging)"

TEST_PATH = re.compile(r"(^|/)tests?(/|$)|\.tests?$")


def header_list(manifest, name):
    m = re.search(r"(?m)^" + name + r":(.*)$", manifest)
    if not m:
        return []
    # split on commas outside quotes (version ranges contain commas)
    return [p.split(";")[0].strip() for p in re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', m.group(1)) if p.strip()]


class Components:
    """Units are folders with a build descriptor: OSGi bundles (META-INF/MANIFEST.MF) and other modules (pom.xml,
    package.json, …). Bundles are grouped into families by name: the own prefix plus the next N name segments
    (family depth, default 2), e.g. org.example.tools.hll.core -> tools.hll for the prefix org.example. The own prefixes
    are inferred from the bundle names unless configured. Other modules form their own family. Aggregator POMs,
    packaging-only modules (features, p2 repositories, target platforms, products), the repository root and built
    products belong to the family "(repository, build & packaging)". Units under a
    tests/ folder (or named *.tests) are test units. Internal dependencies: Require-Bundle, Import-Package (resolved to
    the exporting bundle), Fragment-Host and Maven <dependency> on another module of the repository; references to
    anything outside the repository are ignored. A finding belongs to the unit whose folder is the deepest one
    containing its file; third-party jars in a built product belong to the project bundle that embeds them."""

    def __init__(self, repo, products=(), own_prefixes=None, exclude=(), family_depth=2):
        self.depth = max(1, int(family_depth))
        found = {}
        for f in repo.files:
            if "/node_modules/" in "/" + f:
                continue
            base, d = os.path.basename(f), os.path.dirname(f)
            kind = None
            if f.endswith("META-INF/MANIFEST.MF"):
                d, kind = os.path.dirname(d), "bundle"
            elif base in DESCRIPTORS:
                kind = DESCRIPTORS[base]
            if kind:
                found.setdefault(d or ".", []).append((kind, f))
        self.units = {".": self._unit(".", os.path.basename(repo.root) or "repository", "repository")}
        for d in sorted({f.split("/")[0] for f in repo.files if "/" in f}):
            self.units[d] = self._unit(d, d, "folder")
        exports, maven_names, maven_deps, manifests, feature_plugins = {}, {}, {}, {}, {}
        groups = set()
        for d, items in sorted(found.items()):
            kinds = {k for k, _ in items}
            names, alias = {}, ""
            for k, f in items:
                t = repo.text(f, include_self=True) or ""
                if k == "bundle":
                    t = re.sub(r"\r?\n ", "", t)
                    m = re.search(r"(?m)^Bundle-SymbolicName:\s*([\w.\-]+)", t)
                    if m:
                        names["bundle"] = m.group(1)
                        manifests[d] = t
                elif k == "maven":
                    body = re.sub(
                        r"(?s)<parent>.*?</parent>|<!--.*?-->|<build>.*?</build>|"
                        r"<dependencyManagement>.*?</dependencyManagement>",
                        "",
                        t,
                    )
                    m = re.search(r"<artifactId>\s*([^<\s]+)", body)
                    if m:
                        names["maven"] = m.group(1)
                    g = re.search(r"<groupId>\s*([^<\s]+)", body)
                    if g:
                        groups.add(g.group(1))
                    pk = re.search(r"<packaging>\s*([\w-]+)\s*</packaging>", body)
                    if "<modules>" in body:
                        kinds.add("aggregator")  # parent/aggregator POM: build plumbing
                    elif pk and pk.group(1) in PACKAGING_ONLY:
                        kinds.add("packaging")  # feature, p2 repository, target platform, product
                    maven_deps[d] = re.findall(
                        r"<dependency>\s*(?:<[^>]+>[^<]*</[^>]+>\s*)*?<artifactId>\s*([^<\s]+)", body
                    )
                elif k == "npm":
                    m = re.search(r'"name"\s*:\s*"([^"]+)"', t)
                    if m:
                        names["npm"] = m.group(1)
                elif k == "feature":
                    m = re.search(r'<feature\b[^>]*?\bid="([^"]+)"', t)
                    if m:
                        names["feature"] = m.group(1)
                    feature_plugins[d] = re.findall(r'<plugin\b[^>]*?\bid="([^"]+)"', t)
            if "bundle" in names:
                kind = "bundle"
            elif kinds & {"npm", "python", "go", "rust", "gradle"}:
                kind = next(k for k in KIND_RANK if k in kinds and k not in ("feature", "maven", "aggregator"))
            elif "aggregator" in kinds:
                kind = "aggregator"
            elif "feature" in kinds or "packaging" in kinds:
                kind = "feature" if "feature" in kinds else "packaging"
            else:
                kind = next(k for k in KIND_RANK if k in kinds)
            if kind in ("aggregator", "maven", "packaging") and "bundle" not in names:
                name, alias = os.path.basename(d) or d, names.get("maven", "")
            else:
                name = next(
                    (names[k] for k in ("bundle", "feature", "npm", "maven") if k in names), os.path.basename(d) or d
                )
            u = self._unit(d, name, kind, alias)
            self.units[d] = u
            if "maven" in names:
                maven_names[names["maven"]] = d
        for p in products:
            pid = "product:" + p
            self.units[pid] = self._unit(pid, f"Built product: {p}", "product", path=f"(product {p})")
        self.bsn = {u["name"]: uid for uid, u in self.units.items() if u["kind"] == "bundle"}
        if own_prefixes:
            self.own, self.own_inferred = tuple(own_prefixes), False
        else:
            ids = list(self.bsn) + [u["name"] for u in self.units.values() if u["kind"] == "feature"]
            self.own, self.own_inferred = tuple(infer_own_prefixes(ids or groups)), True
        for d, t in manifests.items():
            for pkg in header_list(t, "Export-Package"):
                exports.setdefault(pkg, d)
        # family, test flag
        for uid, u in self.units.items():
            u["test"] = u["kind"] not in (
                "repository",
                "folder",
                "product",
                "aggregator",
                "packaging",
                "feature",
            ) and bool(TEST_PATH.search(uid))
            if u["kind"] == "bundle":
                u["family"] = self.family_of(u["name"])
            elif u["kind"] in ("npm", "python", "go", "rust", "gradle", "maven"):
                u["family"] = self.family_of(u["name"]) if self.is_own(u["name"]) else u["name"]
            else:
                u["family"] = BUILD_FAMILY
        # internal edges (unit depends on unit)
        self.edges = defaultdict(set)
        for d, t in manifests.items():
            deps = set(self.bsn.get(b) for b in header_list(t, "Require-Bundle") + header_list(t, "Fragment-Host"))
            deps |= {exports.get(p) for p in header_list(t, "Import-Package")}
            self.edges[d] |= {x for x in deps if x and x != d}
        for d, arts in maven_deps.items():
            if self.units[d]["kind"] in ("bundle", "aggregator"):
                continue
            self.edges[d] |= {maven_names[a] for a in arts if a in maven_names and maven_names[a] != d}
        self.features = {
            self.units[d]["name"]: [self.bsn[p] for p in ps if p in self.bsn]
            for d, ps in feature_plugins.items()
            if d in self.units
        }
        self.exclude = list(exclude)
        self._cache = {}

    @staticmethod
    def _unit(uid, name, kind, alias="", path=None):
        return {"id": uid, "name": name, "kind": kind, "alias": alias, "path": path or uid}

    def family_of(self, name):
        for p in sorted(self.own, key=len, reverse=True):
            if name == p or name.startswith(p + "."):
                rest = name[len(p) + 1 :].split(".")
                return ".".join(rest[: self.depth]) if rest != [""] else p
        return ".".join(name.split(".")[: self.depth + 1])

    def is_own(self, name):
        return any(name == p or name.startswith(p + ".") for p in self.own)

    def _resolve_dir(self, d):
        while d:
            if d in self.units:
                return d
            d = os.path.dirname(d)
        return "."

    def resolve(self, where):
        """Unit id for a repository path, a product source label or a '(…)' pseudo location."""
        if where in self._cache:
            return self._cache[where]
        if where.startswith("product:"):
            parts = where.split(":")
            uid = self.bsn.get(parts[2]) if len(parts) > 2 else None
            uid = uid or ("product:" + parts[1] if "product:" + parts[1] in self.units else ".")
        elif where.startswith("("):
            uid = "."
        else:
            uid = self._resolve_dir(os.path.dirname(where))
        self._cache[where] = uid
        return uid

    # -- graph helpers ---------------------------------------------------------------------------
    def dependents(self, start, units):
        """All units (within `units`) that depend on any unit in `start`, directly or transitively."""
        rev = defaultdict(set)
        for a, bs in self.edges.items():
            for b in bs:
                rev[b].add(a)
        seen, todo = set(), list(start)
        while todo:
            x = todo.pop()
            for y in rev[x]:
                if y in units and y not in seen and y not in start:
                    seen.add(y)
                    todo.append(y)
        return seen

    def export(self, checks):
        """Units, families, family edges, impact and the optional exclusion scenario, with finding counts."""
        units = {uid: dict(u, own={}, own_b={}, deps=sorted(self.edges.get(uid, ()))) for uid, u in self.units.items()}
        for c in checks:
            for uid, k in c["by_component"].items():
                units[uid]["own"][c["id"]] = k
            for uid, k in c["by_component_b"].items():
                units[uid]["own_b"][c["id"]] = k

        def counted(members, blocker_level=False):
            """Distinct findings per check in a set of units (a finding shared by several units counts once)."""
            out = {}
            for c in checks:
                shared = [set(x) for x, b in c["shared"] if b or not blocker_level]
                single = Counter(c["by_component_b" if blocker_level else "by_component"])
                for x in shared:
                    for u in x:
                        single[u] -= 1
                k = sum(single[m] for m in members) + sum(1 for x in shared if x & members)
                if k:
                    out[c["id"]] = k
            return out

        # checks that hit more than half of all real units are pervasive (e.g. missing license headers)
        real = [
            u
            for u in units.values()
            if u["kind"] not in ("repository", "folder", "aggregator", "product", "feature", "packaging")
        ]
        hits = Counter(k for u in real for k in u["own"])
        pervasive = sorted(k for k, v in hits.items() if real and v > len(real) / 2)
        blocking = {c["id"] for c in checks if c["status"] == "blocker"} - set(pervasive)
        judging = {c["id"] for c in checks if c["status"] in ("blocker", "judgement", "not_run")} - set(pervasive)

        def state(counts, counts_b):
            if any(k in blocking for k in counts_b):
                return "blocker"
            return "judgement" if any(k in judging for k in counts) else "clear"

        fams = defaultdict(lambda: {"units": [], "tests": []})
        for uid, u in units.items():
            fams[u["family"]]["tests" if u["test"] else "units"].append(uid)
        base = {uid for uid, u in units.items() if not u["test"] and u["family"] != BUILD_FAMILY}
        families = {}
        for name, f in fams.items():
            members = set(f["units"])
            families[name] = {
                "id": name,
                "units": sorted(f["units"], key=lambda x: units[x]["name"]),
                "tests": sorted(f["tests"], key=lambda x: units[x]["name"]),
                "total": counted(members),
                "total_b": counted(members, True),
                "tests_total": counted(set(f["tests"])),
            }
            families[name]["state"] = state(families[name]["total"], families[name]["total_b"])
        fam_edges = Counter()
        for a, bs in self.edges.items():
            for b in bs:
                if a in base and b in base and units[a]["family"] != units[b]["family"]:
                    fam_edges[(units[a]["family"], units[b]["family"])] += 1
        for name, f in families.items():
            f["depends_on"] = sorted(
                ((b, w) for (a, b), w in fam_edges.items() if a == name), key=lambda x: (-x[1], x[0])
            )
            f["used_by"] = sorted(((a, w) for (a, b), w in fam_edges.items() if b == name), key=lambda x: (-x[1], x[0]))
            if name != BUILD_FAMILY:
                dep = self.dependents(set(f["units"]), base)
                f["impact"] = sorted({units[d]["family"] for d in dep} - {name})
                f["impact_units"] = len({d for d in dep if units[d]["family"] != name})
        for uid, u in units.items():
            u["state"] = state(u["own"], u["own_b"])
            u["used_by_transitive"] = len(self.dependents({uid}, base)) if uid in base else 0
        scenario = None
        if self.exclude:
            ex = {
                uid
                for uid, u in units.items()
                if u["kind"] != "folder"
                and uid != "."
                and any(
                    fnmatch.fnmatch(u["name"], p) or fnmatch.fnmatch(uid, p) or fnmatch.fnmatch(u["family"], p)
                    for p in self.exclude
                )
            }
            keep = base - ex
            broken = {
                uid: sorted(set(self.edges.get(uid, ())) & ex) for uid in keep if set(self.edges.get(uid, ())) & ex
            }
            affected = self.dependents(ex, keep)
            test_units = {uid for uid, u in units.items() if u["test"]}
            tests_hit = self.dependents(ex, test_units) | {t for t in test_units if set(self.edges.get(t, ())) & ex}
            split = {
                fid: [b for b in bs if b in ex]
                for fid, bs in self.features.items()
                if any(b in ex for b in bs) and any(b not in ex for b in bs)
            }
            scenario = {
                "patterns": self.exclude,
                "excluded": sorted(ex, key=lambda x: units[x]["name"]),
                "broken": {k: v for k, v in sorted(broken.items(), key=lambda x: units[x[0]]["name"])},
                "affected": sorted(affected - set(broken), key=lambda x: units[x]["name"]),
                "tests": sorted(tests_hit - ex, key=lambda x: units[x]["name"]),
                "features_to_split": split,
                "findings_removed": counted(ex),
            }
        return {
            "units": units,
            "families": families,
            "pervasive": pervasive,
            "blocking": sorted(blocking),
            "edges": len({(a, b) for a, bs in self.edges.items() for b in bs}),
            "scenario": scenario,
            "rule": self.__class__.__doc__.strip().replace("\n    ", " "),
        }
