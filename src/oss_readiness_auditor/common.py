# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Shared constants and helpers: file types, text positions, globs, host-name helpers."""

import fnmatch
import os
import re
from bisect import bisect_right

MAX_FILE_BYTES = 40 * 1024 * 1024

MAX_EVIDENCE = 500  # per check, listed in the report (counts are always complete)

# Only used without git (with git, the tracked files are scanned): build output, IDE metadata, dependency caches.
SKIP_DIRS = {
    ".git",
    "target",
    "node_modules",
    ".metadata",
    "bin",
    "out",
    "build",
    "dist",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    ".gradle",
    ".idea",
    ".m2",
}

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".icns", ".webp"}

BINARY_EXT = {".jar", ".war", ".ear", ".class", ".dll", ".so", ".dylib", ".exe", ".bin", ".zip", ".tar", ".gz", ".7z"}

SOURCE_EXT = {".java", ".xtend", ".js", ".ts", ".tsx", ".jsx", ".py", ".c", ".cpp", ".h", ".kt", ".groovy", ".scala"}


def ext(rel):
    return os.path.splitext(rel)[1].lower()


def line_index(text):
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    return starts


def line_of(starts, pos):
    return bisect_right(starts, pos)


def snippet(text, starts, line, width=160):
    a = starts[line - 1]
    b = text.find("\n", a)
    s = text[a : b if b >= 0 else len(text)].strip()
    return s if len(s) <= width else s[:width] + "…"


def glob_match(path, pattern):
    """Glob on a repository path: '**' spans folders, '*' stays within one; a pattern without '/' matches the file
    name or any folder name on the path."""
    if "/" not in pattern:
        return any(fnmatch.fnmatchcase(seg, pattern) for seg in path.split("/"))
    rx = (
        re.escape(pattern)
        .replace(r"\*\*/", "(?:.*/)?")
        .replace(r"\*\*", ".*")
        .replace(r"\*", "[^/]*")
        .replace(r"\?", "[^/]")
    )
    return re.fullmatch(rx + "(?:/.*)?", path) is not None


DOC_EXT = {
    ".md",
    ".markdown",
    ".adoc",
    ".asciidoc",
    ".rst",
    ".tex",
    ".html",
    ".htm",
    ".xhtml",
    ".txt",
    ".textile",
    ".mediawiki",
    ".bs",
}

CODE_EXT = {
    ".java",
    ".xtend",
    ".kt",
    ".groovy",
    ".scala",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".c",
    ".cpp",
    ".h",
    ".cs",
    ".py",
    ".go",
    ".rs",
}


def compiled(patterns, what):
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.I))
        except re.error as e:
            raise ValueError(f"invalid {what} pattern /{p}/: {e}") from e
    return out


# 'http://org.example.model' style identifiers: reversed domain names, not hosts
REVERSE_DNS = re.compile(
    r"^(org|com|net|edu|gov|mil|int|io|eu|fr|de|ch|at|uk|it|es|nl|be|se|no|dk|fi|pl|cz|jp|cn|ru|"
    r"us|ca|au)\.[\w-]+\.[\w.-]+$"
)

GENERIC_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int",
    "io",
    "eu",
    "info",
    "biz",
    "dev",
    "app",
    "cloud",
    "tech",
    "online",
    "site",
    "xyz",
    "ai",
    "co",
    "me",
    "tv",
    "software",
    "systems",
    "solutions",
    "digital",
    "global",
    "group",
    "company",
    "services",
    "network",
    "local",
    "lan",
    "internal",
    "corp",
    "intra",
    "home",
    "test",
    "example",
    "invalid",
    "localhost",
}


def reverse_dns(host):
    """'org.example.model' – a reversed domain name used as identifier, not a host: starts with a top-level domain
    and does not end with one."""
    last = host.rsplit(".", 1)[-1]
    return bool(REVERSE_DNS.match(host)) and last not in GENERIC_TLDS and len(last) != 2


# Rule texts point here for values that come from the audited repository or the configuration
RUN_REF = '(see "Run and reproducibility")'
