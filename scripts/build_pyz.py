# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
"""Build dist/oss-readiness-audit.pyz: the tool and its pinned dependencies (Jinja2, MarkupSafe) in one file that
runs with any Python 3.11+ and nothing installed:  python3 oss-readiness-audit.pyz <repository>

The archive is reproducible (sorted entries, fixed timestamps), so its SHA-256 can be published and re-checked.
Compiled speed-ups of MarkupSafe are left out (it falls back to its pure-Python implementation), so the file does not
depend on the platform. The dependencies' metadata, including their license texts, is kept in the archive.

Usage: uv run --frozen python scripts/build_pyz.py
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipapp
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "dist", "oss-readiness-audit.pyz")
if "--out" in sys.argv:  # folder for the archive (default: dist/)
    OUT = os.path.join(os.path.abspath(sys.argv[sys.argv.index("--out") + 1]), "oss-readiness-audit.pyz")
EPOCH = (2020, 1, 1, 0, 0, 0)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        stage = os.path.join(tmp, "app")
        reqs = os.path.join(tmp, "requirements.txt")
        # exact versions and hashes from uv.lock
        with open(reqs, "w") as fh:
            subprocess.run(
                ["uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--format", "requirements-txt"],
                cwd=ROOT,
                check=True,
                stdout=fh,
            )
        # One fixed target, whatever machine builds: the chosen wheels' metadata (WHEEL tags) is the same everywhere.
        # Their compiled parts are removed below, so the target does not limit where the archive runs.
        subprocess.run(
            ["uv", "pip", "install", "--quiet", "--target", stage, "--no-deps", "--require-hashes", "-r", reqs]
            + ["--python-platform", "x86_64-manylinux_2_28", "--python-version", "3.13"],
            check=True,
        )
        shutil.copytree(
            os.path.join(ROOT, "src", "oss_readiness_auditor"),
            os.path.join(stage, "oss_readiness_auditor"),
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        for d, dirs, files in os.walk(stage):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for f in files:
                if f.endswith((".so", ".pyd", ".pyc")) or f in ("RECORD", "INSTALLER", "REQUESTED", ".lock"):
                    os.remove(os.path.join(d, f))
            if "__pycache__" in os.listdir(d):
                shutil.rmtree(os.path.join(d, "__pycache__"))
        # deterministic archive: sorted entries with a fixed timestamp
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        raw = os.path.join(tmp, "raw.pyz")
        zipapp.create_archive(stage, raw, interpreter="/usr/bin/env python3", main="oss_readiness_auditor.cli:main")
        with zipfile.ZipFile(raw) as src, open(OUT, "wb") as out:
            out.write(b"#!/usr/bin/env python3\n")
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
                for info in sorted(src.infolist(), key=lambda i: i.filename):
                    new = zipfile.ZipInfo(info.filename, EPOCH)
                    new.external_attr = 0o644 << 16
                    new.compress_type = zipfile.ZIP_DEFLATED
                    dst.writestr(new, src.read(info.filename))
    os.chmod(OUT, 0o755)
    digest = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
    print(f"{digest}  {os.path.relpath(OUT, ROOT) if OUT.startswith(ROOT) else OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
