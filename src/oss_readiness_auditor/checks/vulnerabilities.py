# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
import re
from collections import Counter

from ..common import ext, line_index, line_of, snippet
from ..inventory.osv import SEVERITY_ORDER, OsvDb

ID = "vulnerabilities"
GROUP = "security"
TITLE = "Known vulnerabilities"
ICON = "bug"
# Why the check matters for publication
WHY = "The first outside reader will run the same scan."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "Update affected components to a fixed version or document why an advisory does not apply; fix or justify each "
    "code finding."
)

SCRIPT_EXT = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ""}

CODE_RULES = [
    (
        "high",
        "Remote debugging enabled",
        re.compile(r"-Xdebug\b|-agentlib:jdwp|-Xrunjdwp"),
        {".ini", ".product", ".cfg", ".conf", ".yml", ".yaml", ".properties", ".env", ".json"} | SCRIPT_EXT,
    ),
    (
        "high",
        "OSGi console opened (Eclipse launch argument)",
        re.compile(
            r"(?m)^\s*-console(?:\s+\S+)?\s*$|<programArgs>[^<]*(?<![\w-])-console\b|"
            r"osgi\.console\s*=\s*\S|-Dosgi\.console=\S"
        ),
        {".ini", ".product", ".properties", ".cfg"},
    ),
    (
        "high",
        "Token or certificate validation disabled",
        re.compile(
            r"(?i)setHostnameVerifier\(\s*\(?[^)]*\)?\s*->\s*true|TrustAllCerts|NoopHostnameVerifier|"
            r"ALLOW_ALL_HOSTNAME_VERIFIER|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|"
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
        ),
        {".java", ".xtend", ".kt", ".js", ".ts", ".py"} | SCRIPT_EXT,
    ),
    (
        "medium",
        "SQL built by string concatenation",
        re.compile(
            r"(?i)\"\s*(?:CREATE|DROP|ALTER|GRANT)\s+(?:DATABASE|SCHEMA|USER|ROLE|TABLE)\b[^\"]*\"\s*\+|"
            r"\"\s*(?:SELECT|UPDATE|DELETE|INSERT)\b[^\"]*(?:WHERE|VALUES|SET)[^\"]*\"\s*\+"
        ),
        {".java", ".xtend", ".kt"},
    ),
    (
        "medium",
        "Secret printed to output",
        re.compile(
            r"(?i)\b(?:echo|printf|print|println|console\.log|Write-Host)\b[^\n]*\$\{?\w*(?:PASS|PWD|SECRET|TOKEN)\w*"
        ),
        {".java", ".js", ".py"} | SCRIPT_EXT,
    ),
]


def run(ctx, c):
    repo = ctx.repo
    osv_paths, products = ctx.config.osv_db, ctx.config.products
    c.rule(
        "Components",
        "npm: non-dev packages of every package-lock.json. Maven: direct <dependency> entries of "
        "pom.xml files"
        + (
            ", plus every jar (also nested jars) in the given product folders, identified by "
            "META-INF/maven/**/pom.properties or a documented bundle-name mapping"
            if products
            else ""
        )
        + (". Committed jars (also inside zip archives), identified the same way")
        + ".",
    )
    c.rule(
        "Advisories",
        "OSV.dev database dumps given with --osv-db, matched offline: exact version lists and "
        "ECOSYSTEM/SEMVER ranges (introduced / fixed / last_affected). Severity: the advisory's own rating "
        "(GitHub: LOW/MODERATE/HIGH/CRITICAL). Advisories sharing a CVE/GHSA alias count once.",
    )
    for sev, name, rx, _exts in CODE_RULES:
        c.rule(f"Code/config ({sev}): {name}", "/" + rx.pattern + "/ – commented-out lines are skipped")
    comps = ctx.third_party
    # --- third-party advisories
    rows, matched = [], []
    if osv_paths:
        db = OsvDb(osv_paths, {(e, n) for (e, n, v) in comps})
        groups = []
        for (e, n, v), sources in sorted(comps.items()):
            for adv in db.match(e, n, v):
                ids = set([adv["id"]] + adv["aliases"])
                g = next((g for g in groups if g["ids"] & ids), None)
                rec = {"eco": e, "name": n, "version": v, "sources": sorted(sources), **adv}
                if g:
                    g["ids"] |= ids
                    g["recs"].append(rec)
                else:
                    groups.append({"ids": ids, "recs": [rec]})

        def gsev(g):
            return min((r["severity"] for r in g["recs"]), key=SEVERITY_ORDER.index)

        for g in sorted(groups, key=lambda g: (SEVERITY_ORDER.index(gsev(g)), g["recs"][0]["name"])):
            r = g["recs"][0]
            cves = sorted(i for i in g["ids"] if i.startswith("CVE-"))
            if c.add(
                r["sources"][0],
                None,
                where=sorted({s for rr in g["recs"] for s in rr["sources"]}),
                text=f"{r['name']} {r['version']} – {(cves or [r['id']])[0]}: {r['summary']}"
                + (f" (fixed in {', '.join(r['fixed'][:3])})" if r["fixed"] else ""),
                tag=gsev(g).lower(),
                level=None if gsev(g) in ("CRITICAL", "HIGH") else "judgement",
                match=f"{r['name']} {r['version']} " + " ".join(sorted(g["ids"])),
            ):
                matched.append(g)
        origins = sorted({src_kind(s) for g in matched for r in g["recs"] for s in r["sources"]})
        for o in origins:
            sel = [g for g in matched if any(src_kind(s) == o for r in g["recs"] for s in r["sources"])]
            cnt = Counter(gsev(g) for g in sel)
            rows.append([o] + [cnt.get(s, 0) for s in SEVERITY_ORDER])
        tot = Counter(gsev(g) for g in matched)
        rows.append(["All (unique advisories)"] + [tot.get(s, 0) for s in SEVERITY_ORDER])
        c.tables.append(
            {
                "caption": "Third-party advisories by origin",
                "columns": ["Origin"] + [s.title() for s in SEVERITY_ORDER],
                "rows": rows,
                "severity": True,
                "note": "Published advisories, not assessed for exploitability. A component may be unreachable "
                "in practice; that assessment is part of the review.",
            }
        )
        db_info = db.info
    else:
        db_info = []
    # --- own code / configuration
    code = Counter()
    for f in repo.files:
        e = ext(f)
        for sev, name, rx, exts in CODE_RULES:
            if e not in exts:
                continue
            t = repo.text(f)
            if not t or (e == "" and not t.startswith("#!") and not os.path.basename(f).startswith("Dockerfile")):
                continue
            starts = None
            hit_lines = set()
            for m in rx.finditer(t):
                starts = starts or line_index(t)
                ln = line_of(starts, m.start())
                if ln in hit_lines:
                    continue
                hit_lines.add(ln)
                if re.match(r"\s*(#|//|\*|<!--|REM\b|::)", snippet(t, starts, ln, 400)):
                    continue  # commented out
                if c.add(
                    f,
                    ln,
                    f"{name}: {snippet(t, starts, ln, 120)}",
                    "code-" + sev,
                    level=None if sev == "high" else "judgement",
                ):
                    code[sev] += 1
    c.tables.append(
        {
            "caption": "Own code and configuration (rule-based)",
            "columns": ["", "Critical", "High", "Medium", "Low", "Unrated"],
            "rows": [["Pattern matches", 0, code["high"], code["medium"], code["low"], 0]],
            "severity": True,
            "note": "Pattern matches need a manual look: e.g. a debug flag in a developer launch file is harmless.",
        }
    )
    tot = Counter()
    for g in matched:
        tot[min((r["severity"] for r in g["recs"]), key=SEVERITY_ORDER.index)] += 1
    ctx.osv_info = db_info
    if osv_paths:
        c.figure = str(len(matched))
        c.figure_label = (
            f"published advisories in {len({(r['name']) for g in matched for r in g['recs']})} components – "
            f"{tot['CRITICAL']} critical"
        )
        c.finding = (
            f"{len(comps)} third-party components checked offline against {sum(i['advisories'] for i in db_info):,} "
            f"advisories. {len(matched)} unique advisories apply. Rule-based review of the project's own code "
            f"and configuration: {code['high']} high, {code['medium']} medium, {code['low']} low pattern matches."
        )
        c.status = (
            "blocker"
            if tot["CRITICAL"] or tot["HIGH"] or code["high"]
            else ("judgement" if matched or sum(code.values()) else "clear")
        )
    else:
        c.figure = "–"
        c.figure_label = "advisory check not run (no --osv-db given)"
        c.finding = (
            f"{len(comps)} third-party components found; the advisory check needs the OSV dumps (--osv-db). "
            f"Rule-based review of the project's own code: {code['high']} high, {code['medium']} medium, "
            f"{code['low']} low pattern matches."
        )
        c.status = "not_run" if not code["high"] else "blocker"
    return c


def src_kind(source):
    if source.startswith("product:"):
        return "Product " + source.split(":")[1]
    if source.endswith("package-lock.json"):
        return "npm: " + source
    if source.lower().endswith((".jar", ".zip")):
        return "Committed jars"
    return "Maven (pom.xml, direct)"
