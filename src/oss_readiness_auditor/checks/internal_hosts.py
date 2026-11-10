# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import os
import re
from collections import defaultdict

from ..common import IMAGE_EXT, ext, line_index, line_of, reverse_dns

ID = "internal-hosts"
GROUP = "security"
TITLE = "Internal infrastructure references"
ICON = "server"
# Why the check matters for publication
WHY = "Nobody outside the organisation can reach internal systems – and their names do not belong in public."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = "Remove internal host names or move them into configuration; keep only documented public endpoints."

URL = re.compile(
    r"(?i)\b(?:https?|ldaps?|ftp|jdbc:[a-z]+|ssh|git)://(?:[^\s/@\"'<>]+@)?([a-z0-9][a-z0-9.\-]*\.[a-z]{2,}|"
    r"\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?"
)

GIT_SSH = re.compile(r"\bgit@([a-z0-9][a-z0-9.\-]*\.[a-z]{2,}):")


LOCAL_HOSTS = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|[\w.-]+\.(?:localhost|test|invalid|example))$")

INTERNAL_TLDS = {"local", "lan", "internal", "intranet", "corp", "home", "intra", "private"}


PRIVATE_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


# Generated dependency lockfiles: their registry and download links are third-party metadata, not references of
# the project's own.
LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
}


def host_rules(config):
    pub = config.pack_values("public_hosts")
    public = re.compile(r"(?i)(^|\.)(" + "|".join(re.escape(h).replace(r"\*", r"[\w-]+") for h in pub) + r")$")
    hints = config.pack_values("internal_host_hints")
    internal = re.compile(r"(?i)(^|[.\-])(" + "|".join(re.escape(h) for h in hints) + r")(\d*)([.\-]|$)")
    return public, internal, pub, hints


def run(ctx, c):
    repo = ctx.repo
    public, internal_rx, pub, hints = host_rules(ctx.config)
    c.rule("Hosts", "Host names in URLs (http, https, ldap, ftp, jdbc, ssh, git) and git@host: remotes in text files.")
    c.rule(
        "Lockfiles",
        "Dependency lockfiles (" + ", ".join(sorted(LOCKFILES)) + ") are skipped: registry and download links of "
        "third-party packages.",
    )
    c.rule(
        "Public allow-list",
        "Hosts under these domains, localhost and reserved names (.local, .test, .example, "
        ".invalid) and reversed-domain identifiers such as http://org.example.model are not reported: "
        + ", ".join(pub)
        + ".",
    )
    c.rule(
        "Internal hint",
        "Hosts with one of these name parts (optionally followed by digits; the top-level domain is "
        "not considered), hosts in the top-level domains " + ", ".join(sorted(INTERNAL_TLDS)) + ", and private IP "
        "ranges are marked 'internal-looking': " + ", ".join(hints) + ".",
    )
    hosts = defaultdict(lambda: {"count": 0, "files": set(), "first": None})
    for f in repo.files:
        if os.path.basename(f) in LOCKFILES:
            continue
        t = repo.text(f)
        if not t or ext(f) in IMAGE_EXT:
            continue
        starts = None
        for rx in (URL, GIT_SSH):
            for m in rx.finditer(t):
                h = m.group(1).lower().rstrip(".")
                if public.search(h) or LOCAL_HOSTS.match(h) or reverse_dns(h):
                    continue
                e = hosts[h]
                e["count"] += 1
                e["files"].add(f)
                if not e["first"]:
                    starts = starts or line_index(t)
                    e["first"] = (f, line_of(starts, m.start()))
    internal = {
        h
        for h in hosts
        if (
            PRIVATE_IP.match(h)
            if re.match(r"^\d+(\.\d+){3}$", h)
            else internal_rx.search(h.rsplit(".", 1)[0]) or h.rsplit(".", 1)[-1] in INTERNAL_TLDS
        )
    }
    rows = []
    for h, e in sorted(hosts.items(), key=lambda x: (x[0] not in internal, -x[1]["count"], x[0])):
        tag = "internal-looking" if h in internal else "other host"
        if c.add(
            e["first"][0], e["first"][1], h, tag, where=sorted(e["files"]), level=None if h in internal else "judgement"
        ):
            rows.append([h, tag, e["count"], len(e["files"])])
        else:
            internal.discard(h)
    n_int = len(internal)
    c.figure = str(n_int)
    c.figure_label = f"internal-looking hosts (of {len(rows)} non-public hosts)"
    c.finding = (
        f"{len(rows)} host names outside the public allow-list, {n_int} of them internal-looking. "
        "Each needs a decision: remove, replace by configuration, or keep as a documented public endpoint."
    )
    c.tables.append({"caption": "Hosts", "columns": ["Host", "Kind", "Occurrences", "Files"], "rows": rows[:80]})
    c.status = "blocker" if n_int else ("judgement" if rows else "clear")
    return c
