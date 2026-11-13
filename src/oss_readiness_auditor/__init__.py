# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""
OSS readiness auditor for Eclipse extensions.

Independent, offline, deterministic check of a source tree – typically an Eclipse/OSGi/Tycho code base such as an
RCP application or a Papyrus, Sirius or Capella extension – for the issues that block publishing it as open source.
Every finding comes from a documented rule (regular expression or file check) listed in the report; there is no
network access, no AI and no third-party Python package.

Project facts (own bundle prefixes, product names) are inferred from the repository and shown in the report; a small
TOML file (--config) can override them, enable optional rule packs, add rules and acknowledge reviewed findings.

Usage (plain Python 3.11+ or uv, see README.md):
    python3 oss_readiness_auditor.py <repository> [-o report.html] [--config oss-readiness.toml]
                                     [--product <unpacked product dir>]...          # also inventory a build
                                     [--osv-db Maven-all.zip --osv-db npm-all.zip]   # offline vulnerability data
                                     [--json]                                       # also write the findings as JSON
    python3 oss_readiness_auditor.py <repository> --init-config > oss-readiness.toml  # start a configuration

Output: one static, self-contained HTML page (no external resources; readable without JavaScript).
Secrets and personal data are masked.
"""

TOOL_NAME = "OSS readiness auditor for Eclipse extensions"

TOOL_ID = "oss-readiness-auditor-for-eclipse-extension"

TOOL_VERSION = "1.1.0"
