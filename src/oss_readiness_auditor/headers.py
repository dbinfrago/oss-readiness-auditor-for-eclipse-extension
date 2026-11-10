# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""License headers and Eclipse metadata: header extraction, normalisation, MANIFEST and NLS parsing."""

import re

from .common import CODE_EXT, ext, line_index, line_of

COMMENT_NOISE = re.compile(r"(?m)^[ \t]*(?:/\*+|\*+/|\*|//+|#+|<!--|-->|--|;+|'|REM\b|::)[ \t]?")

# Eclipse metadata that carries license, copyright and branding text anywhere in the file
ECLIPSE_FULLTEXT = re.compile(
    r"(?i)(^|/)(about\.(?:html|ini|properties|mappings)|feature\.(?:xml|properties)|"
    r"plugin\.properties|bundle\.properties|[^/]+\.product|[^/]+\.genmodel|"
    r"\.settings/[^/]+\.prefs|license\.(?:txt|html)|notice\.(?:txt|html|md))$"
)

CODE_TEMPLATE = re.compile(r"(^|/)\.settings/[^/]+\.prefs$|\.genmodel$")

LICENSE_GRANT = re.compile(
    r"(?i)SPDX-License-Identifier|made\s+available\s+under\s+the\s+terms\s+of|Eclipse\s+Public\s+License|"
    r"Licensed\s+under\s+the\s+Apache\s+License|Licensed\s+to\s+the\s+Apache\s+Software\s+Foundation|"
    r"Permission\s+is\s+hereby\s+granted|GNU\s+(?:Lesser\s+|Library\s+|Affero\s+)?General\s+Public\s+License|"
    r"Mozilla\s+Public\s+License|Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms|"
    r"Common\s+Public\s+License|Eclipse\s+Distribution\s+License|Creative\s+Commons|"
    r"This\s+(?:program|file|library|software)\s+is\s+free\s+software|"
    r"(?:provided|licen[sc]ed|released|distributed|available)\s+under\s+(?:the\s+)?(?:terms\s+of\s+(?:the\s+)?)?"
    r"(?:EPL|EDL|ASL|Apache|MIT|BSD|L?GPL|AGPL|MPL|CDDL|ISC|Unlicense|CC0|Eclipse)\b"
)

COPYRIGHT = re.compile(r"(?i)copyright\s*(?:\(c\)|©)?\s*(\d{4})(?:\s*[-–,]\s*(\d{4}))?\s*,?\s*([^\n*]{2,80})")

SPDX_LIC = re.compile(r"SPDX-" r"License-Identifier:\s*([^\s*\"<>]+)")

SPDX_CR = re.compile(r"SPDX-" "FileCopyrightText:")

HEADER_CHARS = 6000


def header_of(text, rel):
    """The leading part of a file that holds its license header: for code, everything before the first
    package/import statement (at most HEADER_CHARS characters); otherwise the first HEADER_CHARS characters."""
    head = text[:HEADER_CHARS]
    if ext(rel) in CODE_EXT:
        m = re.search(r"(?m)^\s*(?:package|import|from\s+\S+\s+import|#include|using|namespace)\b", head)
        if m and m.start() > 0:
            head = head[: m.start()]
    return head


def normalise(text):
    text = COMMENT_NOISE.sub("", text)
    text = text.replace("\\n", " ").replace("\\t", " ").replace("\\r", " ")
    text = re.sub(r"&#x?[0-9A-Fa-f]+;|<[^>]{0,200}>", " ", text)
    return re.sub(r"\s+", " ", text)


def holder_name(raw):
    h = re.sub(r"\s+", " ", raw or "").strip(" .,;*")
    return h or "(not named)"


def locate(text, matched):
    """Line of `matched` (taken from normalised text) in the original text: first words, any separators."""
    words = re.findall(r"\w+", matched)[:4]
    if not words:
        return 1
    m = re.search(r"\W+".join(re.escape(w) for w in words), text, re.I)
    return line_of(line_index(text), m.start()) if m else 1


def manifest_entries(manifest, name):
    """Entries of a MANIFEST.MF header as (name, attributes) – continuation lines joined, quoted commas kept."""
    m = re.search(r"(?m)^" + name + r":(.*)$", re.sub(r"\r?\n ", "", manifest))
    if not m:
        return []
    out = []
    for p in re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', m.group(1)):
        if p.strip():
            head, _, attrs = p.partition(";")
            out.append((head.strip(), attrs))
    return out


def nls_resolver(repo, folder, bases):
    """Resolve %key values from the default (non-localised) properties files of a bundle or feature folder."""
    props = {}
    for b in bases:
        f = (folder + "/" if folder not in (".", "") else "") + b
        if f in repo.files:
            for m in re.finditer(r"(?m)^[ \t]*([\w.\-]+)[ \t]*[=:][ \t]*((?:.*\\\r?\n)*.*)$", repo.text(f) or ""):
                props.setdefault(m.group(1), re.sub(r"\\\r?\n\s*", "", m.group(2)).strip())
    return lambda v: props.get(v[1:].strip(), v) if v and v.startswith("%") else v
