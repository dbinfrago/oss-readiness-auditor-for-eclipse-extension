# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Access to the audited repository: tracked files, text content, git history."""

import os
import re
import subprocess

from .common import BINARY_EXT, IMAGE_EXT, MAX_FILE_BYTES, SKIP_DIRS, ext, glob_match


class Repo:
    """Tracked files of the repository (git ls-files if available, else a directory walk)."""

    def __init__(self, root, exclude=()):
        self.root = os.path.abspath(root)
        self.git = None
        files = self._list()
        self.excluded = [f for f in files if any(glob_match(f, g) for g in exclude)] if exclude else []
        ex = set(self.excluded)
        self.files = [f for f in files if f not in ex]
        self._cache = {}
        self.skipped_self = set()
        self.extensions = {ext(f)[1:] for f in self.files if ext(f)}

    def _list(self):
        if os.path.isdir(os.path.join(self.root, ".git")) or os.path.isfile(os.path.join(self.root, ".git")):
            try:
                out = subprocess.run(["git", "-C", self.root, "ls-files", "-z"], capture_output=True, check=True).stdout
                head = subprocess.run(
                    ["git", "-C", self.root, "rev-parse", "HEAD"], capture_output=True, text=True
                ).stdout.strip()
                dirty = subprocess.run(
                    ["git", "-C", self.root, "status", "--porcelain", "--untracked-files=no"],
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                self.git = {"head": head, "modified_tracked_files": len(dirty.splitlines()) if dirty else 0}
                files = [f for f in out.decode("utf-8", "replace").split("\0") if f]
                return sorted(f for f in files if os.path.isfile(os.path.join(self.root, f)))
            except (OSError, subprocess.CalledProcessError):
                pass
        files = []
        for d, dirs, names in os.walk(self.root):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
            for n in names:
                files.append(os.path.relpath(os.path.join(d, n), self.root).replace(os.sep, "/"))
        return sorted(files)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def text(self, rel, include_self=False):
        """File content as text, or None for binary/oversized files and (unless asked) for copies of this tool,
        whose rule definitions would otherwise match its own rules."""
        if rel in self._cache:
            t = self._cache[rel]
            return t if include_self or t is None or not is_auditor_source(t) else None
        p = self.path(rel)
        try:
            if os.path.getsize(p) > MAX_FILE_BYTES or ext(rel) in BINARY_EXT | IMAGE_EXT - {".svg"}:
                return None
            with open(p, "rb") as fh:
                raw = fh.read()
        except OSError:
            return None
        if b"\0" in raw[:8192]:
            return None
        t = raw.decode("utf-8", "replace")
        if len(self._cache) < 400:
            self._cache[rel] = t
        if not include_self and is_auditor_source(t):
            self.skipped_self.add(rel)
            return None
        return t

    def git_authors(self):
        """E-mail address of the author of every commit (git history), or None without git."""
        if not self.git:
            return None
        try:
            out = subprocess.run(
                ["git", "-C", self.root, "log", "--format=%ae"], capture_output=True, text=True, check=True
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            return None
        return [x.strip().lower() for x in out.splitlines() if x.strip()]

    def git_log_bodies(self):
        if not self.git:
            return None
        try:
            out = subprocess.run(
                ["git", "-C", self.root, "log", "--format=%H%x00%B%x01"], capture_output=True, text=True, check=True
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            return None
        return [c.split("\0", 1) for c in out.split("\x01") if "\0" in c]


# Source files of this tool carry this line in their header. Their rule definitions (patterns of credentials,
# notices, …) would otherwise match the rules themselves when the tool's own repository is audited. Skipped files
# are listed in the report, so the marker cannot hide content unnoticed.
AUDITOR_MARK = re.compile(r"(?m)^(?:#|\{#) oss-readiness-auditor: rule source(?: #\})?$")


def is_auditor_source(text):
    return AUDITOR_MARK.search(text[:400]) is not None
