# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
"""Generate docs/METHODS.md: every check with its purpose, resolution and complete rule set, as the report shows them.

The rules are taken from a run on an empty repository with the default configuration and all rule packs enabled, so
the document lists every built-in rule. A test fails when the document is out of date.

Usage: uv run --frozen python scripts/methods.py            (writes docs/METHODS.md)
       uv run --frozen python scripts/methods.py --check    (exit 1 if docs/METHODS.md is out of date)
"""

import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from oss_readiness_auditor import TOOL_NAME  # noqa: E402
from oss_readiness_auditor.audit import build_report  # noqa: E402
from oss_readiness_auditor.checks import ALL  # noqa: E402
from oss_readiness_auditor.config import LEVELS, Config  # noqa: E402
from oss_readiness_auditor.packs import PACKS  # noqa: E402
from oss_readiness_auditor.repo import Repo  # noqa: E402

OUT = os.path.join(ROOT, "docs", "METHODS.md")


def md(text):
    """Literal text in Markdown: escape what Markdown would interpret (backslashes, emphasis, code, links, HTML,
    GitHub maths and strikethrough), so that regular expressions are shown exactly when rendered."""
    return re.sub(r"([\\*_`\[\]<$~&])", r"\\\1", text)


def generate():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "methods.toml")
        with open(cfg, "w") as fh:
            fh.write("[project]\nname_patterns = ['<product name>']\nown_prefixes = ['org.example']\n")
            fh.write("[packs]\nenable = [" + ", ".join(f'"{p}"' for p in PACKS) + "]\n")
        repo_dir = os.path.join(tmp, "empty")
        os.makedirs(repo_dir)
        data = build_report(Repo(repo_dir), Config(cfg, {}), quiet=True)
    rules = {c["id"]: c["rules"] for c in data["checks"]}
    groups = {g["id"]: g["title"] for g in data["groups"]}
    out = [
        "<!--",
        # REUSE-IgnoreStart (the header of the generated file, not of this one)
        "SPDX-FileCopyrightText: 2026 DB InfraGO AG",
        "SPDX-License-Identifier: Apache-2.0",
        # REUSE-IgnoreEnd
        "-->",
        "",
        f"# Methods of the {TOOL_NAME}",
        "",
        "Generated from the code by `scripts/methods.py` – do not edit. Every check is one module in",
        "`src/oss_readiness_auditor/checks/`; built-in knowledge is in the rule packs in `src/oss_readiness_auditor/packs/`.",
        "The rules below are those of the default configuration with all rule packs enabled; a report lists the rules",
        "of its own run. Every check can be configured in `[checks.<id>]`: `enabled`, `level` (how much its findings",
        "weigh) and its own settings; `--spawn-config` writes all of them with their effective values.",
        "",
        "**Levels:** " + "; ".join(f"`{k}` – {v}" for k, v in LEVELS.items()) + ".",
        "",
        "## Rule packs",
        "",
        "| Pack | Default | Contents |",
        "|---|---|---|",
    ]
    for name, p in PACKS.items():
        default = "always" if p.get("locked") else ("on" if p["default"] else "off")
        out.append(f"| `{name}` | {default} | {p['about']} |")
    out += ["", "## Checks", ""]
    for m in ALL:
        out += [f"- [{m.TITLE}](#{m.ID}) – `{m.ID}`, {groups[m.GROUP]}"]
    for m in ALL:
        src = os.path.relpath(m.__file__, ROOT).replace(os.sep, "/")
        out += ["", f'<a id="{m.ID}"></a>', "", f"### {m.TITLE}", "", f"Source: [`{src}`](../{src})", ""]
        out += [f"**Why it matters:** {m.WHY}", "", f"**To resolve:** {m.RESOLVE}", ""]
        if getattr(m, "PACK", None):
            out += [f"Runs only with the rule pack `{m.PACK}`.", ""]
        settings = '`enabled` (default `true`), `level` (default `"default"`)'
        for key, o in getattr(m, "OPTIONS", {}).items():
            settings += f", `{key}` (default `{json.dumps(o['default'])}`): {md(o['about'])}"
        out += [f"**Settings** (`[checks.{m.ID}]`): {settings}.", "", "**Rules:**", ""]
        for r in rules.get(m.ID, []):
            out.append(f"- **{md(r['name'])}:** {md(r['detail'])}")
    return "\n".join(out) + "\n"


def main():
    text = generate()
    if "--check" in sys.argv:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if current != text:
            print("docs/METHODS.md is out of date: run  uv run --frozen python scripts/methods.py", file=sys.stderr)
            return 1
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"written {os.path.relpath(OUT, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
