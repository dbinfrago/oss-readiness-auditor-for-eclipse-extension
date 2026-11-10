# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
"""Configuration, rule packs, acknowledged findings and inference of project facts."""

import json
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixture import FIXTURE, A, build, files, run, texts  # noqa: E402


class ConfiguredTest(unittest.TestCase):
    def test_config_overrides_and_suppressions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            data, c = run(
                root,
                textwrap.dedent("""\
                [project]
                own_prefixes = ["com.acme"]
                name_patterns = ['\\bWidget\\b']
                vendors = ["ACME Corp"]
                [packs]
                enable = ["rail"]
                disable = ["lang-fr"]
                [checks.reuse-dco]
                reuse = "blocker"
                [rules]
                public_hosts = ["status.acme.com"]
                [[suppress]]
                check = "secrets"
                path = "config/*.properties"
                reason = "test value, rotated"
                [[suppress]]
                check = "internal-hosts"
                text = "gitlab"
                reason = "public mirror"
                """),
            )
            cfg = data["config"]
            self.assertEqual(cfg["own_prefixes"], ["com.acme"])
            self.assertEqual(cfg["own_prefixes_source"], "config file")
            self.assertIn("rail", cfg["packs"])
            self.assertNotIn("lang-fr", cfg["packs"])
            # French clause no longer recognised once lang-fr is disabled
            self.assertNotIn("features/com.acme.widget.feature/feature.properties", files(c["license-notices"]))
            self.assertEqual(c["secrets"]["evidence_total"], 0)
            self.assertEqual(c["secrets"]["status"], "clear")
            self.assertEqual(len(c["secrets"]["suppressed"]), 1)
            rows = {r[0] for r in c["internal-hosts"]["tables"][0]["rows"]}
            self.assertNotIn("gitlab.acme.com", rows)
            self.assertNotIn("status.acme.com", rows)
            self.assertEqual(sorted(files(c["domain-data"])), ["data/other.xml", "data/station.railml"])
            self.assertEqual(c["reuse-dco"]["status"], "blocker")
            self.assertEqual(texts(c["eclipse-metadata"], "bundle vendor"), ["Other Vendor GmbH"])
            self.assertEqual([s["used"] for s in cfg["suppress"]], [1, 1])

    def test_cli_own_prefix_replaces_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            data, _ = run(root, own_prefix=["com.other"])
            self.assertEqual(data["config"]["own_prefixes"], ["com.other"])
            self.assertEqual(data["config"]["own_prefixes_source"], "command line")

    def test_example_config_is_valid(self):
        here = os.path.dirname(os.path.abspath(__file__))
        cfg = A.Config(os.path.join(here, "..", "examples", "oss-readiness.toml"), {})
        self.assertNotIn("lang-de", cfg.active_packs)
        self.assertEqual(len(cfg.suppressions), 2)

    def test_check_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            data, c = run(
                root,
                textwrap.dedent("""\
                [checks.secrets]
                level = "info"
                [checks.ownership]
                level = "blocker"
                [checks.internal-hosts]
                level = "judgement"
                [checks.namespace]
                enabled = false
                [checks.project-basics]
                required = ["LICENSE", "README", "SECURITY"]
                """),
            )
            self.assertEqual(c["secrets"]["status"], "info")
            self.assertEqual(c["secrets"]["evidence_total"], 1)  # still shown
            self.assertEqual(c["ownership"]["status"], "blocker")
            self.assertEqual(c["internal-hosts"]["status"], "judgement")
            self.assertNotIn("namespace", c)
            self.assertEqual(data["config"]["disabled_checks"], ["namespace"])
            self.assertEqual(c["project-basics"]["status"], "blocker")  # SECURITY missing
            self.assertIn("Criticality", [r["name"] for r in c["secrets"]["rules"]])
            # an escalated check counts against the units like a blocker
            self.assertIn("ownership", data["components"]["blocking"])

    def test_pack_sets_check_defaults_and_config_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            data, c = run(root, pack=["openrail"])
            settings = {(s["check"], s["key"]): s for s in data["config"]["checks"]}
            self.assertEqual(settings[("project-basics", "required")]["source"], "pack openrail")
            self.assertIn("openrail", c)
            data, c = run(root, '[packs]\nenable = ["openrail"]\n[checks.project-basics]\nrequired = ["LICENSE"]\n')
            s = next(s for s in data["config"]["checks"] if s["key"] == "required")
            self.assertEqual((s["value"], s["source"]), (["LICENSE"], "configuration file"))

    def test_invalid_check_settings_are_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "c.toml")
            for text in (
                "[checks.no-such-check]\nenabled = false\n",
                "[checks.secrets]\nlevel = 'fatal'\n",
                "[checks.secrets]\nseverity = 'blocker'\n",
                "[checks.project-basics]\nrequired = ['LICENCE']\n",
                "[checks.openrail]\ntarget_stage = 3\n",
                "[checks.secrets]\nenabled = 'no'\n",
            ):
                with open(p, "w") as fh:
                    fh.write(text)
                with self.assertRaises(ValueError, msg=text):
                    A.Config(p, {})

    def test_unknown_config_key_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "c.toml")
            with open(p, "w") as fh:
                fh.write("[project]\nown_prefix = ['x']\n")
            with self.assertRaises(ValueError):
                A.Config(p, {})

    def test_spawn_config_is_valid_toml(self):
        import tomllib

        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            config = A.Config(None, {})
            text = A.spawn_config(A.Repo(root), config)
            parsed = tomllib.loads(text)
            self.assertEqual(parsed["project"]["own_prefixes"], ["com.acme.widget"])
            p = os.path.join(tmp, "c.toml")
            with open(p, "w") as fh:
                fh.write(text)
            A.Config(p, {})  # round trip
            # spawned from an existing configuration: its check settings are carried over, uncommented
            with open(p, "w") as fh:
                fh.write("[packs]\nenable = ['openrail']\n[checks.openrail]\ntarget_stage = 2\n")
            text = A.spawn_config(A.Repo(root), A.Config(p, {}))
            parsed = tomllib.loads(text)
            self.assertEqual(parsed["checks"]["openrail"], {"target_stage": 2})
            self.assertEqual(parsed["packs"]["enable"], ["openrail"])
            self.assertIn("# required = ['LICENSE', 'README', 'CODE_OF_CONDUCT', 'MAINTAINERS']", text)


class InferenceTest(unittest.TestCase):
    def test_single_vendor_prefix(self):
        self.assertEqual(
            A.infer_own_prefixes(["org.example.tools.a", "org.example.core.b", "org.example.rcp"]), ["org.example"]
        )

    def test_shared_organisation_root(self):
        names = [f"org.eclipse.papyrus.{x}" for x in ("uml.diagram", "infra.core", "views", "sysml")]
        self.assertEqual(A.infer_own_prefixes(names), ["org.eclipse.papyrus"])

    def test_shared_root_with_outliers(self):
        names = [f"org.polarsys.capella.{x}" for x in "abcdefghijklmnopqrst"] + ["org.polarsys.kitalpha.x"]
        self.assertEqual(A.infer_own_prefixes(names), ["org.polarsys.capella", "org.polarsys.kitalpha.x"])

    def test_two_organisations(self):
        names = ["com.acme.a", "com.acme.b", "de.other.tool.x", "de.other.tool.y"]
        self.assertEqual(A.infer_own_prefixes(names), ["com.acme", "de.other.tool"])

    def test_own_domains(self):
        self.assertEqual(
            A.own_domains(["org.eclipse.papyrus", "fr.example"]), [("eclipse.org", "papyrus"), ("example.fr", "")]
        )

    def test_glob(self):
        self.assertTrue(A.glob_match("a/b/c.txt", "**/c.txt"))
        self.assertTrue(A.glob_match("c.txt", "**/c.txt"))
        self.assertTrue(A.glob_match("a/node/x", "node"))
        self.assertTrue(A.glob_match("lscb/app/x/y.js", "lscb/app"))
        self.assertFalse(A.glob_match("a/b/c.txt", "a/*.txt"))

    def test_redact(self):
        self.assertEqual(A.redact('path="C:/Users/ab12345/Desktop/x"'), 'path="C:/Users/a***/Desktop/x"')
        self.assertEqual(A.redact("mail jane.smith@acme.com"), "mail j***@acme.com")
        self.assertNotIn("Sup3rS3cret", A.redact("db.password=Sup3rS3cret!"))
        self.assertEqual(A.redact('password="changeme"'), 'password="changeme"')

    def test_evidence_is_redacted_in_every_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(dict(FIXTURE, **{"docs/more.md": "Acme Widget Studio files in C:/Users/ab12345/acme\n"}), root)
            data, _ = run(root)
            self.assertNotIn("ab12345", json.dumps(data["checks"]))
            self.assertNotIn("Sup3rS3cret", json.dumps(data))

    def test_reverse_dns(self):
        self.assertTrue(A.reverse_dns("org.example.model"))
        self.assertFalse(A.reverse_dns("de.wikipedia.org"))
        self.assertFalse(A.reverse_dns("fr.example.com"))
        self.assertFalse(A.reverse_dns("build.example.de"))


if __name__ == "__main__":
    unittest.main()
