# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
"""What each check must find, and must not find, in the fixture."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixture import FIXTURE, A, build, files, run, texts  # noqa: E402


# REUSE-IgnoreStart
class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = os.path.join(cls.tmp.name, "acme-widget")
        build(FIXTURE, cls.root)
        cls.data, cls.c = run(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_inferred_project_facts(self):
        cfg = self.data["config"]
        self.assertEqual(cfg["own_prefixes"], ["com.acme.widget"])
        self.assertEqual(cfg["own_prefixes_source"], "inferred")
        self.assertEqual(cfg["name_patterns_source"], "inferred")
        self.assertIn("Acme\\s+Widget\\s+Studio", cfg["name_patterns"][0])
        self.assertNotIn("rail", cfg["packs"])

    def test_license_notices(self):
        c = self.c["license-notices"]
        f = files(c)
        self.assertIn("bundles/com.acme.widget.core/src/com/acme/widget/core/Handler.java", f)
        self.assertIn("bundles/com.acme.widget.core/src/com/acme/widget/core/Arr.java", f)
        self.assertIn("features/com.acme.widget.feature/feature.properties", f)
        self.assertNotIn("bundles/com.acme.widget.core/src/com/acme/widget/core/Epl.java", f)
        self.assertNotIn("bundles/com.acme.widget.core/src/com/acme/widget/core/Model.java", f)
        holders = dict(map(tuple, c["tables"][0]["rows"]))
        self.assertEqual(holders.get("ACME Corp"), 1)
        self.assertEqual(holders.get("ACME SA"), 1)
        self.assertEqual(c["status"], "blocker")

    def test_ownerless(self):
        f = files(self.c["ownerless"])
        self.assertIn("bundles/com.acme.widget.core/src/com/acme/widget/core/NoOwner.java", f)
        self.assertNotIn("bundles/com.acme.widget.core/src/com/acme/widget/core/Gen.java", f)
        self.assertNotIn("bundles/com.acme.widget.core/src/com/acme/widget/core/Sidecar.java", f)

    def test_remnants(self):
        t = texts(self.c["remnants"])
        for name in (
            "com.acme.widget.core.MissingView",
            "com.acme.widget.removed",
            "com.acme.widget.gone",
            "com.acme.widget.missing",
            "com.acme.widget.extra.feature",
            "com.acme.widget.gone.feature",
            "bundles/gone",
        ):
            self.assertIn(name, t)
        for name in (
            "org.eclipse.ui.ExternalView",
            "org.eclipse.core.runtime",
            "org.eclipse.ui",
            "com.acme.widget.ui.api",
            "com.acme.widget.core.Handler",
            "org.osgi.framework",
        ):
            self.assertNotIn(name, t)

    def test_eclipse_metadata(self):
        c = self.c["eclipse-metadata"]
        self.assertEqual(texts(c, "bundle vendor"), ["ACME Corp", "Other Vendor GmbH"])
        self.assertIn("features/com.acme.widget.other.feature/feature.xml", files(c, "feature without license"))
        self.assertNotIn("features/com.acme.widget.feature/feature.xml", files(c, "feature without license"))
        self.assertEqual(files(c, "about.html missing"), ["bundles/com.acme.widget.ui/META-INF/MANIFEST.MF"])

    def test_eclipse_metadata_accepted_vendor(self):
        c = self.c["eclipse-metadata"]
        self.assertIn("ACME Corp", texts(c, "bundle vendor") + texts(c, "feature provider"))

    def test_namespace(self):
        t = texts(self.c["namespace"])
        self.assertEqual(sorted(t), ["http://www.eclipse.org/acme/widget", "http://www.omg.org/spec/Foo"])

    def test_secrets(self):
        c = self.c["secrets"]
        self.assertEqual(c["evidence_total"], 1)
        self.assertEqual(files(c), ["config/app.properties"])

    def test_hosts(self):
        rows = {r[0]: r[1] for r in self.c["internal-hosts"]["tables"][0]["rows"]}
        self.assertEqual(rows.get("gitlab.acme.com"), "internal-looking")
        self.assertEqual(rows.get("db.acme.local"), "internal-looking")
        self.assertEqual(rows.get("status.acme.com"), "other host")
        self.assertNotIn("www.eclipse.org", rows)
        self.assertNotIn("pypi.internal.acme.com", rows)
        self.assertNotIn("download.eclipse.org", rows)

    def test_personal_data(self):
        c = self.c["personal-data"]
        self.assertIn("j***@acme.com", texts(c, "e-mail"))
        self.assertEqual(len(texts(c, "e-mail")), 1)
        self.assertEqual(len(texts(c, "user path")), 1)

    def test_ownership(self):
        self.assertIn("docs/notes.md", files(self.c["ownership"]))

    def test_code_rules(self):
        t = " ".join(texts(self.c["vulnerabilities"]))
        self.assertIn("OSGi console opened", t)
        self.assertIn("Remote debugging enabled", t)

    def test_name_logo(self):
        c = self.c["name-logo"]
        imgs = files(c, "logo / branding image")
        self.assertIn("docs/logo.png", imgs)
        self.assertIn("releng/splash.bmp", imgs)  # Eclipse splash screen
        self.assertIn("bundles/com.acme.widget.core/icons/app16.png", imgs)  # window icon declared in the .product
        self.assertIn("docs/notes.md", files(c, "name: documentation"))
        self.assertIn("releng/widget.product", files(c, "name: product branding"))
        self.assertTrue(c["resolve"])

    def test_third_party_target(self):
        self.assertIn("releng/widget.target", files(self.c["third-party"]))

    def test_committed_jars(self):
        c = self.c["third-party"]
        rows = {r[0]: r for t in c["tables"] if t["caption"] == "Committed jars" for r in t["rows"]}
        snap = rows["releng/patch/org.eclipse.gizmo.core-2.0.0-SNAPSHOT.jar"]
        self.assertEqual(
            snap[1:],
            [
                "org.eclipse.gizmo.core",
                "2.0.0.202601011200",
                "locally built upstream bundle",
                "EPL-2.0 (from about.html)",
            ],
        )
        self.assertEqual(
            rows["releng/patch.zip › org.eclipse.gizmo.core-2.0.0-SNAPSHOT.jar"][3], "locally built upstream bundle"
        )
        self.assertEqual(
            rows["releng/lib/widgets-lib-1.2.3.jar"][1:4], ["org.widgets:widgets-lib", "1.2.3", "third-party"]
        )
        self.assertEqual(rows["releng/own/com.acme.widget.core_1.0.0.jar"][3], "own build")
        self.assertIn("Gizmo Core (Eclipse Gizmo)", " ".join(texts(c)))  # %keys resolved from the jar
        # the jars are no longer anonymous binaries
        self.assertNotIn("releng/lib/widgets-lib-1.2.3.jar", files(c, "committed binary"))
        self.assertIn("releng/patch.zip", files(c, "committed binary"))

    def test_foundation_namespace(self):
        self.assertEqual(texts(self.c["namespace"], "foundation namespace"), [])  # com.acme.widget is not

    def test_domain_data_needs_pack(self):
        self.assertNotIn("domain-data", self.c)

    def test_policy_defaults(self):
        self.assertEqual(self.c["reuse-dco"]["status"], "judgement")
        self.assertEqual(self.c["project-basics"]["status"], "judgement")


class NamesTest(unittest.TestCase):
    def test_bundle_under_a_foundation_root(self):
        extra = {"bundles/org.polarsys.widget.x/META-INF/MANIFEST.MF": "Bundle-SymbolicName: org.polarsys.widget.x\n"}
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(dict(FIXTURE, **extra), root)
            _, c = run(root)
            self.assertEqual(
                texts(c["namespace"], "foundation namespace"),
                ["org.polarsys.widget.x – Eclipse Foundation (PolarSys) namespace (1 bundle(s))"],
            )
            _, c = run(root, '[project]\nhosted_by = ["org.polarsys"]\n')
            self.assertEqual(texts(c["namespace"], "foundation namespace"), [])

    def test_name_from_bundle_headers_without_product(self):
        single = {
            "plugin/META-INF/MANIFEST.MF": "Bundle-SymbolicName: org.example.xyz.tools\nBundle-Name: %name\n"
            "Bundle-Vendor: XYZ\n",
            "plugin/plugin.properties": "name=XYZ Diagram Tools\n",
            "README.md": "The XYZ tools.\n",
        }
        many = {
            f"b{i}/META-INF/MANIFEST.MF": f"Bundle-SymbolicName: org.example.b{i}\nBundle-Name: Part {i}\n"
            for i in range(5)
        }
        many["b0/META-INF/MANIFEST.MF"] = "Bundle-SymbolicName: org.example.b0\nBundle-Name: AQL Support\n"
        with tempfile.TemporaryDirectory() as tmp:
            build(single, os.path.join(tmp, "one"))
            build(many, os.path.join(tmp, "many"))
            self.assertEqual(A.infer_name_patterns(A.Repo(os.path.join(tmp, "one")))[1], ["XYZ"])
            # one bundle's acronym among many is not the product's name
            self.assertEqual(A.infer_name_patterns(A.Repo(os.path.join(tmp, "many"))), ([], []))


class OpenRailTest(unittest.TestCase):
    def results(self, extra=None, **cli):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(dict(FIXTURE, **(extra or {})), root)
            data, c = run(root, pack=["openrail"], **cli)
        rows = c["openrail"]["tables"][0]["rows"]
        return c, {r[1]: r[2] for r in rows}

    def test_without_pack_the_check_does_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "acme-widget")
            build(FIXTURE, root)
            self.assertNotIn("openrail", run(root)[1])

    def test_stage_1(self):
        c, r = self.results()
        self.assertEqual(r["OSI-approved license"], "met")  # EPL-2.0 text
        self.assertEqual(r["Only openly licensed code"], "not met")  # proprietary clauses in the fixture
        self.assertEqual(r["Maintainers"], "not met")
        self.assertEqual(r["Code of conduct"], "not met")
        self.assertEqual(r["Scope"], "needs a person")
        self.assertEqual(c["openrail"]["status"], "blocker")
        # stage 2 criteria are shown, but only stage 1 counts
        self.assertTrue(c["openrail"]["figure"].endswith("/7"))
        self.assertNotIn("Stage 2", " ".join(texts(c["openrail"])))

    def test_stage_2_files_and_ci(self):
        extra = {
            "MAINTAINERS.md": "Jane\n",
            "CODE_OF_CONDUCT.md": "We adopt the OpenRail Association Code of Conduct.\n",
            "SECURITY.md": "Report privately.\n",
            "CHANGELOG.md": "## 1.0\n",
            "ROADMAP.md": "Next\n",
            "GOVERNANCE.md": "Decisions\n",
            ".github/dependabot.yml": "version: 2\n",
            ".github/dco.yml": "require:\n  members: false\n",
            ".github/workflows/ci.yml": "steps:\n  - uses: fsfe/reuse-action@v5\n  - uses: actions/attest-build-provenance@v2\n",
            "tools/uv.lock": "version = 1\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "c.toml")
            with open(cfg, "w") as fh:
                fh.write("[packs]\nenable = ['openrail']\n[checks.openrail]\ntarget_stage = 2\n")
            root = os.path.join(tmp, "acme-widget")
            build(dict(FIXTURE, **extra), root)
            data, c = run(root, open(cfg).read())
        r = {row[1]: row[2] for row in c["openrail"]["tables"][0]["rows"]}
        for name in (
            "Maintainers",
            "Code of conduct",
            "Security policy",
            "Changelog",
            "Public roadmap",
            "Open governance",
            "Automated dependency updates",
            "DCO checked automatically",
            "REUSE linter automated",
            "Signed release artifacts",
        ):
            self.assertEqual(r[name], "met", name)
        self.assertEqual(r["Dependencies pinned"], "needs a person")  # Maven build, despite the lockfile
        self.assertEqual(r["REUSE compliant"], "not met")
        self.assertEqual(r["SBOM for release artifacts"], "not met")
        sbom = [e for e in c["openrail"]["evidence"] if "SBOM" in e["text"]]
        self.assertEqual(sbom[0]["tag"], "not met")  # recommended only: listed, but needs judgement
        self.assertTrue(c["openrail"]["figure"].endswith("/23"))
        self.assertIn("Stage 2: REUSE compliant", " ".join(texts(c["openrail"], "not met")))


class WordingTest(unittest.TestCase):
    """The default language packs on header wordings seen in real code bases (owners anonymised)."""

    @classmethod
    def setUpClass(cls):
        cfg = A.Config(None, {})
        cls.props = A.compiled(cfg.pack_values("proprietary"), "proprietary")

    def holder(self, text):
        norm = A.normalise(text)
        m = next((x for x in (r.search(norm) for r in self.props) if x), None)
        return None if m is None else A.holder_name(m.groupdict().get("holder"))

    def test_proprietary(self):
        cases = {
            " * These files are the property of ACME LIST, their use is subject to specific\n * agreement.": "ACME LIST",
            " * are property of the ACME, their use is subject to specific agreement": "ACME",
            "#  The content is the property of ACME Labs. Any distribution is forbidden": "ACME Labs",
            " * This program is the Confidential and Proprietary product of Acme Global Services": "Acme Global Services",
            "Ce document est la propri\u00e9t\u00e9 de Acme SA. Son utilisation est soumise \u00e0 un accord": "Acme SA",
            "Diese Datei ist Eigentum der Acme GmbH. Alle Rechte vorbehalten.": "Acme GmbH",
            " * Any use is subject to specific agreement with ACME.": "(not named)",
        }
        for text, holder in cases.items():
            self.assertEqual(self.holder(text), holder, text)

    def test_not_proprietary(self):
        for text in (
            " * The value is the property of the element, see Foo.",
            " * Returns true if this is a property of a UML class.",
            " * Copyright (c) 2020 ACME. All rights reserved. This program and the accompanying materials are "
            "made available under the terms of the Eclipse Public License 2.0",
            "une propri\u00e9t\u00e9 de s\u00e9curit\u00e9 est v\u00e9rifi\u00e9e",
        ):
            self.assertIsNone(self.holder(text), text)

    def test_license_grant(self):
        for text in (
            "(c) Copyright ACME 2018-2022. Provided under the EPL-v2",
            "Licensed under the Apache License, Version 2.0",
            "SPDX-License-Identifier: MIT",
        ):
            self.assertTrue(A.LICENSE_GRANT.search(text), text)


# REUSE-IgnoreEnd


if __name__ == "__main__":
    unittest.main()
