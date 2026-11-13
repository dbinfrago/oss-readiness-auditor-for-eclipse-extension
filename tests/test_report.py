# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
"""The report: escaping of repository content, package data, determinism, generated method documentation."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixture import FIXTURE, SRC, A, build, report_html, run  # noqa: E402


class EscapingTest(unittest.TestCase):
    """Content of the audited repository must never become markup or script in the report."""

    PAYLOAD = "<script>alert(1)</script>\"'><img src=x onerror=alert(2)>"

    def test_hostile_repository_content_is_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            p = self.PAYLOAD
            hostile = dict(FIXTURE)
            hostile.update(
                {
                    # file name, snippet, holder, host, vendor, unit name, product name, move-out pattern, config text
                    f"docs/{p.replace('/', '_')}.md": f"These files are the property of Evil {p}, their use is subject to x\n",
                    "docs/hosts.md": f"see https://gitlab.evil.example.com/{p} and Acme Widget Studio {p}\n",
                    "bundles/evil/META-INF/MANIFEST.MF": f"Bundle-SymbolicName: com.acme.widget.evil\nBundle-Vendor: {p}\n",
                    "releng/evil.product": f'<product name="Evil {p.replace(chr(34), "")}" uid="x"/>\n',
                }
            )
            build(hostile, root)
            cfg = os.path.join(tmp, "c.toml")
            with open(cfg, "w") as fh:
                fh.write(f'[[suppress]]\ncheck = "ownership"\nreason = {json.dumps(p)}\n')
            data, _ = run(root, move_out=[f"*{p}*"], own_prefix=[f"com.acme{p}"])
            html = A.render_html(data)
            config = A.Config(cfg, {"move_out": ["com.acme.widget.evil*"]})
            data2 = A.build_report(A.Repo(root), config, quiet=True)
            html2 = A.render_html(data2)
        for out in (html, html2):
            self.assertEqual(out.count("<script>"), 1)  # the report's own script only
            self.assertNotIn("<img", out)
            self.assertNotIn("<script>alert", out)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", out)


class StructureTest(unittest.TestCase):
    def test_section_order_and_no_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            data, _ = run(root, move_out=["com.acme.widget.ui*"])
            html = A.render_html(data)
        import re

        sections = re.findall(r'<section class="[^"]*" id="(\w+)"', html)
        self.assertEqual(sections, ["glance", "details", "hotspots", "method", "run"])
        for gone in ("<svg xmlns", 'class="fam', 'class="unit', "Component graph", "Families"):
            self.assertNotIn(gone, html)
        self.assertIn("Scenario: moving units out", html)

    def test_clear_checks_get_no_card_and_links_resolve(self):
        import re

        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "gizmo")
            # REUSE-IgnoreStart
            build(
                {
                    "LICENSE": "Apache License\nVersion 2.0\n",
                    "README.md": "# Gizmo\n",
                    "src/Main.java": "// SPDX-License-Identifier: Apache-2.0\npackage a;\nclass Main {}\n",
                },
                root,
            )
            # REUSE-IgnoreEnd
            data, c = run(root)
            html = A.render_html(data)
        clear = [k for k, v in c.items() if v["status"] == "clear"]
        self.assertIn("secrets", clear)
        for k in clear:
            self.assertNotIn(f'id="c-{k}"', html)  # no card in Details
            self.assertIn(f'id="m-{k}"', html)  # its rules stay in Method
        self.assertIn('id="c-project-basics"', html)  # expected files missing: needs judgement
        self.assertIn("Not shown, because no rule matched", html)
        ids = set(re.findall(r'id="([^"]+)"', html))
        for target in re.findall(r'href="#([^"]+)"', html):
            self.assertIn(target, ids, target)


class SingleFileTest(unittest.TestCase):
    def test_pyz_runs_from_a_relative_path_with_dotdot(self):
        """The single-file build reads its templates and assets from the archive, however it is started."""
        import shutil
        import subprocess

        if not shutil.which("uv"):
            self.skipTest("uv not available")
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(
                ["uv", "run", "--frozen", "python", "scripts/build_pyz.py", "--out", tmp],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            work = os.path.join(tmp, "work")
            build(FIXTURE, os.path.join(work, "repo"))
            r = subprocess.run(
                [sys.executable, os.path.join("..", "oss-readiness-audit.pyz"), "repo", "-o", "r.html", "--quiet"],
                cwd=work,
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            self.assertIn('id="hotspots"', open(os.path.join(work, "r.html"), encoding="utf-8").read())


class PackageDataTest(unittest.TestCase):
    def test_every_icon_used_exists(self):
        from oss_readiness_auditor.checks import ALL
        from oss_readiness_auditor.findings import GROUPS

        names = {c.ICON for c in ALL} | {g["icon"] for g in GROUPS} | {s[1] for s in report_html.STATUS_META.values()}
        names |= {
            "files",
            "search",
            "arrow-right",
            "octagon-alert",
            "puzzle",
            "package-search",
            "landmark",
            "clipboard-check",
            "circle-check",
        }
        self.assertEqual(sorted(names - set(report_html.icons())), [])

    def test_packs_load(self):
        from oss_readiness_auditor.packs import ORDER, PACKS

        self.assertEqual(list(PACKS), list(ORDER))
        self.assertTrue(all("about" in p and "default" in p for p in PACKS.values()))


class DeterminismTest(unittest.TestCase):
    def test_same_findings_under_different_hash_seeds(self):
        """Same repository + same tool + same configuration = same data, whatever Python's string hashing does."""
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            out = []
            for seed in ("1", "2"):
                o = os.path.join(tmp, f"r{seed}.html")
                env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=SRC)
                cmd = [sys.executable, "-m", "oss_readiness_auditor", root, "-o", o, "--json", "--quiet"]
                subprocess.run(cmd, check=True, env=env)
                with open(o[:-5] + ".json", encoding="utf-8") as fh:
                    d = json.load(fh)
                d["run"].pop("time_utc")
                d["run"].pop("data_sha256")
                out.append(d)
            self.assertEqual(out[0], out[1])


class MethodsDocTest(unittest.TestCase):
    def test_methods_document_is_up_to_date(self):
        import subprocess

        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        r = subprocess.run(
            [sys.executable, os.path.join(root, "scripts", "methods.py"), "--check"], capture_output=True
        )
        self.assertEqual(r.returncode, 0, r.stderr.decode())


if __name__ == "__main__":
    unittest.main()
