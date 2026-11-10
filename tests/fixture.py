# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
"""Shared test fixture: a synthetic Eclipse extension ("ACME Widget") built in a temporary folder.

Every fixture file states what the rules must find (or must not find). The fixture is generated rather than committed
so that this repository itself does not carry proprietary notices, credentials or personal data.
Run the tests: uv run python -m unittest discover -s tests
"""

import io
import json
import os
import sys
import textwrap
import zipfile

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, SRC)
from oss_readiness_auditor import audit, cli, common, config, headers, infer, masking, repo  # noqa: E402
from oss_readiness_auditor.report import html as report_html  # noqa: E402


class A:  # the names the tests use, wherever they live in the package
    Config, Repo, build_report = config.Config, repo.Repo, audit.build_report
    render_html, spawn_config = report_html.render_html, cli.spawn_config
    infer_own_prefixes, own_domains = infer.infer_own_prefixes, infer.own_domains
    infer_name_patterns = infer.infer_name_patterns
    glob_match, reverse_dns, compiled = common.glob_match, common.reverse_dns, common.compiled
    redact, normalise, holder_name = masking.redact, headers.normalise, headers.holder_name
    LICENSE_GRANT = headers.LICENSE_GRANT


# The fixtures below contain license, copyright and SPDX text of the fictitious project; it is not this file's own.
# REUSE-IgnoreStart
EPL = """/*******************************************************************************
 * Copyright (c) 2020 ACME Corp. All rights reserved.
 * This program and the accompanying materials are made available under the terms of the Eclipse Public License 2.0
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
"""


FIXTURE = {
    "LICENSE": "Eclipse Public License - v 2.0\n",
    "README.md": "# Acme Widget\n",
    "pom.xml": """<project><modelVersion>4.0.0</modelVersion><groupId>com.acme.widget</groupId>
        <artifactId>com.acme.widget.parent</artifactId><name>Acme Widget</name><packaging>pom</packaging>
        <modules><module>bundles/com.acme.widget.core</module><module>bundles/gone</module></modules></project>""",
    # --- bundle with a vendor resolved from plugin.properties, dangling references, about.html present
    "bundles/com.acme.widget.core/META-INF/MANIFEST.MF": textwrap.dedent("""\
        Manifest-Version: 1.0
        Bundle-SymbolicName: com.acme.widget.core;singleton:=true
        Bundle-Vendor: %providerName
        Require-Bundle: org.eclipse.core.runtime,
         com.acme.widget.removed
        Import-Package: com.acme.widget.gone;version="1.0",
         com.acme.widget.ui.api;resolution:=optional,
         org.osgi.framework
        Export-Package: com.acme.widget.core
        """),
    "bundles/com.acme.widget.core/plugin.properties": "providerName=ACME Corp\n",
    "bundles/com.acme.widget.core/about.html": "<html><body>EPL-2.0</body></html>\n",
    "bundles/com.acme.widget.core/plugin.xml": """<plugin>
        <extension point="org.eclipse.ui.handlers"><handler class="com.acme.widget.core.Handler"/></extension>
        <extension point="org.eclipse.ui.views"><view class="com.acme.widget.core.MissingView"/></extension>
        <extension point="org.eclipse.ui.views"><view class="org.eclipse.ui.ExternalView"/></extension>
        </plugin>""",
    # proprietary (English) -> license-notices, holder "ACME Corp"
    "bundles/com.acme.widget.core/src/com/acme/widget/core/Handler.java": "/*\n * Copyright 2020 ACME Corp.\n * These files are the property of ACME Corp, their use is subject to specific\n"
    " * agreement.\n */\npackage com.acme.widget.core;\npublic class Handler {}\n",
    # EPL with "All rights reserved" -> licensed, not flagged
    "bundles/com.acme.widget.core/src/com/acme/widget/core/Epl.java": EPL
    + "package com.acme.widget.core;\nclass Epl {}\n",
    # "All rights reserved" without any license -> flagged
    "bundles/com.acme.widget.core/src/com/acme/widget/core/Arr.java": "// Copyright 2020 ACME Corp. All rights reserved.\npackage com.acme.widget.core;\nclass Arr {}\n",
    # no header -> ownerless
    "bundles/com.acme.widget.core/src/com/acme/widget/core/NoOwner.java": "package com.acme.widget.core;\nclass NoOwner {}\n",
    # generated (EMF marker) -> not ownerless
    "bundles/com.acme.widget.core/src/com/acme/widget/core/Gen.java": "package com.acme.widget.core;\n/** @generated */\nclass Gen {}\n",
    # no header, but a REUSE side-car file naming the owner -> not ownerless
    "bundles/com.acme.widget.core/src/com/acme/widget/core/Sidecar.java": "package com.acme.widget.core;\nclass S {}\n",
    "bundles/com.acme.widget.core/src/com/acme/widget/core/Sidecar.java.license": "SPDX-FileCopyrightText: 2020 ACME Corp\nSPDX-License-Identifier: EPL-2.0\n",
    # dependency lockfile: registry links are not the project's hosts
    "tools/uv.lock": 'source = { registry = "https://pypi.internal.acme.com/simple" }\n',
    # 'property of' in a class comment after the package statement, lower-case object -> not a license clause
    "bundles/com.acme.widget.core/src/com/acme/widget/core/Model.java": EPL
    + "package com.acme.widget.core;\n/** The value is the property of the element, set by Foo. */\nclass Model {}\n",
    # --- second bundle: other vendor, no about.html
    "bundles/com.acme.widget.ui/META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nBundle-SymbolicName: com.acme.widget.ui\nBundle-Vendor: Other Vendor GmbH\n",
    # --- features
    "features/com.acme.widget.feature/feature.xml": """<?xml version="1.0"?>
        <feature id="com.acme.widget.feature" label="Acme Widget" provider-name="%providerName">
        <license url="%licenseURL">%license</license>
        <plugin id="com.acme.widget.core"/><plugin id="com.acme.widget.missing"/><plugin id="org.eclipse.ui"/>
        <includes id="com.acme.widget.extra.feature"/>
        </feature>""",
    "features/com.acme.widget.feature/feature.properties": "providerName=ACME Corp\nlicenseURL=license.html\nlicense=Ce logiciel est la propri\u00e9t\u00e9 de ACME SA. "
    "Son utilisation est soumise \u00e0 un accord \u00e9crit.\n",
    "features/com.acme.widget.other.feature/feature.xml": '<feature id="com.acme.widget.other.feature" provider-name="ACME Corp"><plugin id="com.acme.widget.ui"/></feature>',
    # --- models: one own, two foreign namespaces, one hostless
    "model/widget.ecore": '<ecore:EPackage nsURI="http://www.eclipse.org/acme/widget"/>\n'
    '<ecore:EPackage nsURI="http://acme.com/widget/1.0"/>\n'
    '<ecore:EPackage nsURI="http://www.omg.org/spec/Foo"/>\n'
    '<ecore:EPackage nsURI="http:///local.ecore"/>\n',
    # --- configuration: a credential, a placeholder, an internal host, a public host
    "config/app.properties": "password=Sup3rS3cret!\nother.password=changeme\n"
    "db.url=jdbc:postgresql://db.acme.local:5432/x\nscm=https://gitlab.acme.com/widget\n"
    "doc=https://www.eclipse.org/legal\nstatus=https://status.acme.com/\n",
    # --- launch configuration: OSGi console and remote debugging
    "releng/widget.product": '<product name="Acme Widget Studio" uid="com.acme.widget.product">\n'
    "<launcherArgs><programArgs>-console 5555</programArgs>\n"
    "<vmArgs>-Xdebug -Xrunjdwp:transport=dt_socket</vmArgs></launcherArgs>\n"
    '<windowImages i16="/com.acme.widget.core/icons/app16.png"/>\n'
    '<features><feature id="com.acme.widget.feature"/><feature id="com.acme.widget.gone.feature"/></features>\n'
    "</product>\n",
    # --- documentation: personal data, a confidentiality notice, the product name
    "docs/notes.md": "Contact jane.smith@acme.com or someone@example.com. Logs in /home/jsmith/workspace.\n"
    "CONFIDENTIAL - do not distribute.\nAcme Widget Studio is great. icon@2x.png\n",
    "docs/logo.png": "",
    "releng/splash.bmp": "",
    "bundles/com.acme.widget.core/icons/app16.png": "",
    # --- domain data (only with the rail pack)
    "data/station.railml": "<railml/>\n",
    "data/other.xml": '<?xml version="1.0"?><railml xmlns="x"/>\n',
    # --- a target platform
    "releng/widget.target": '<target><locations><location type="InstallableUnit">'
    '<unit id="org.eclipse.platform.feature.group" version="0.0.0"/>'
    '<repository location="https://download.eclipse.org/releases/2024-06"/></location>'
    "</locations></target>",
}


def jar(entries):
    """A jar (zip) in memory: {name: text or bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


# committed jars: a patched (development) build of someone else's bundle, a Maven library, an own build – and the
# patched bundle again inside a zip archive
UPSTREAM_SNAPSHOT_JAR = jar(
    {
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nBundle-SymbolicName: org.eclipse.gizmo.core;singleton:=true\n"
        "Bundle-Version: 2.0.0.202601011200\nBundle-Name: %pluginName\nBundle-Vendor: %providerName\n",
        "plugin.properties": "pluginName=Gizmo Core\nproviderName=Eclipse Gizmo\n",
        "about.html": "<p>Provided under the terms of the Eclipse Public License Version 2.0</p>",
    }
)
FIXTURE.update(
    {
        "releng/patch/org.eclipse.gizmo.core-2.0.0-SNAPSHOT.jar": UPSTREAM_SNAPSHOT_JAR,
        "releng/lib/widgets-lib-1.2.3.jar": jar(
            {
                "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Title: Widgets Lib\n",
                "META-INF/maven/org.widgets/widgets-lib/pom.properties": "groupId=org.widgets\n"
                "artifactId=widgets-lib\nversion=1.2.3\n",
            }
        ),
        "releng/own/com.acme.widget.core_1.0.0.jar": jar(
            {"META-INF/MANIFEST.MF": "Bundle-SymbolicName: com.acme.widget.core\nBundle-Version: 1.0.0.qualifier\n"}
        ),
        "releng/patch.zip": jar({"org.eclipse.gizmo.core-2.0.0-SNAPSHOT.jar": UPSTREAM_SNAPSHOT_JAR}),
    }
)


def build(files, root):
    for rel, content in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(content, bytes):
            with open(p, "wb") as fh:
                fh.write(content)
            continue
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)


def run(root, config_text=None, **cli):
    path = None
    if config_text is not None:
        path = os.path.join(root, "..", "cfg.toml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(config_text)
    config = A.Config(path, cli)
    repo = A.Repo(root, config.exclude)
    data = A.build_report(repo, config, quiet=True)
    A.render_html(data)  # must render
    json.dumps(data)  # must serialise
    return data, {c["id"]: c for c in data["checks"]}


def texts(check, tag=None):
    return [e["text"] for e in check["evidence"] if e.get("issue", True) and (tag is None or e["tag"] == tag)]


def files(check, tag=None):
    return [e["file"] for e in check["evidence"] if e.get("issue", True) and (tag is None or e["tag"] == tag)]


# REUSE-IgnoreEnd
