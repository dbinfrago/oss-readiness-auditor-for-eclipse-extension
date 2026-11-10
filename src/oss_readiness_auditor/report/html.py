# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Static HTML report: prepares the report data for the Jinja templates in templates/.

Markup lives in the templates; values from the audited repository are escaped automatically (autoescape). Only the
style sheet, script and icon shapes of this package are inserted unescaped (`Markup`)."""

import json
import os
import re
from collections import Counter
from functools import cache
from importlib import resources

from jinja2 import Environment, FunctionLoader, StrictUndefined
from markupsafe import Markup

from ..common import MAX_EVIDENCE

STATUS_META = {
    "blocker": ("Blocker found", "octagon-alert"),
    "judgement": ("Needs judgement", "circle-question-mark"),
    "clear": ("Clear", "circle-check"),
    "not_run": ("Not run", "circle-slash"),
    "info": ("For information", "info"),
}
SEV_CLASS = {"Critical": "c", "High": "h", "Medium": "m", "Low": "l", "Unrated": "u"}
SOURCE_LABEL = {
    "inferred": "inferred from {}",
    "config file": "set in the configuration file",
    "command line": "set on the command line",
}
KIND_LABEL = {
    "repository": "repository",
    "folder": "folder",
    "bundle": "OSGi bundle",
    "feature": "feature",
    "aggregator": "Maven aggregator",
    "maven": "Maven module",
    "npm": "npm package",
    "python": "Python package",
    "go": "Go module",
    "rust": "Rust crate",
    "gradle": "Gradle project",
    "product": "built product",
    "packaging": "packaging module",
}
HOTSPOTS = 20  # units in the hotspot table


@cache
def asset(name):
    return resources.files(__package__).joinpath("assets", name).read_text(encoding="utf-8")


@cache
def icons():
    return json.loads(asset("icons.json"))


def icon(name, cls="i"):
    """Inline SVG icon (shapes from icons.json, a file of this package)."""
    return Markup(
        f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{icons().get(name, "")}</svg>'
    )


def anchor(prefix, key):
    return prefix + "-" + re.sub(r"[^A-Za-z0-9_-]", "-", key)


def compact(html):
    """Remove the line breaks and indentation of the templates between tags (they are not part of the content)."""
    return Markup(re.sub(r">[ \t]*\n\s*<", "><", str(html)).strip())


def environment():
    env = Environment(
        # read through importlib.resources, like the assets: works from a wheel, a folder and the single-file .pyz
        loader=FunctionLoader(lambda name: resources.files(__package__).joinpath("templates", name).read_text("utf-8")),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        finalize=lambda v: "" if v is None else v,
    )
    env.filters["num"] = lambda v: f"{v:,}"
    env.filters["fmt"] = lambda v: f"{v:,}" if isinstance(v, int) else v
    env.filters["anchor"] = anchor
    env.filters["plural"] = lambda n, one="", many="s": one if n == 1 else many
    env.tests["wide_table"] = lambda t: bool(t.get("severity")) or len(t["columns"]) > 3
    env.globals.update(
        icon=icon,
        STATUS_META=STATUS_META,
        SEV_CLASS=SEV_CLASS,
        KIND_LABEL=KIND_LABEL,
        MAX_EVIDENCE=MAX_EVIDENCE,
    )
    return env


ENV = environment()


def source_label(source, inferred_from):
    return SOURCE_LABEL.get(source, source).format(inferred_from)


def components_view(data):
    """What the hotspot section shows: units with findings in blocker checks, ranked, and the move-out scenario."""
    checks, comp = data["checks"], data["components"]
    units = comp["units"]
    cby = {c["id"]: c for c in checks}
    blocking = set(comp["blocking"])

    def ranked(counts):
        """Findings in blocker checks (pervasive checks excluded): what ranks the units."""
        return sum(v for k, v in counts.items() if k in blocking)

    hot = [u for u in units.values() if u["own"] and ranked(u["own_b"]) and u["kind"] not in ("folder", "repository")]
    hot.sort(key=lambda u: (-ranked(u["own_b"]), -u["used_by_transitive"], u["name"]))
    return {
        "units": units,
        "scen": comp["scenario"],
        "edges": comp["edges"],
        "ranked": ranked,
        "hot": hot[:HOTSPOTS],
        "n_hot": len(hot),
        "legend": [c for c in checks if any(c["id"] in u["own"] for u in units.values())],
        "pervasive": ", ".join(cby[k]["title"] for k in sorted(comp["pervasive"])),
        "n_units": sum(1 for u in units.values() if u["kind"] not in ("repository", "folder")),
    }


def render_html(data):
    checks, run = data["checks"], data["run"]
    repo_name = os.path.basename(os.path.normpath(run["repository"])) or run["repository"]
    view = {
        "data": data,
        "checks": checks,
        "run": run,
        "tool": data["tool"],
        "cfg": data["config"],
        "repo_name": repo_name,
        "count": Counter(c["status"] for c in checks),
        "groups": [(g, [c for c in checks if c["group"] == g["id"]]) for g in data["groups"]],
        "comp": components_view(data),
        "source_label": source_label,
        "unused_suppressions": [
            f"#{i + 1} ({s['check']})" for i, s in enumerate(data["config"]["suppress"]) if not s["used"]
        ],
    }
    body = compact(ENV.get_template("body.html.j2").render(view))
    return ENV.get_template("page.html.j2").render(
        title=f"Open-source readiness – {repo_name}",
        css=Markup(asset("report.css").rstrip("\n")),
        script=Markup(asset("report.js").rstrip("\n")),
        body=body,
    )
