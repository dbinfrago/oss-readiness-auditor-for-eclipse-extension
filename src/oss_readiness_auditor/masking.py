# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Masking of credentials, e-mail addresses and user names in everything the report shows."""

import re


def mask_secret(value):
    v = value.strip()
    if len(v) <= 4:
        return "****"
    return v[:2] + "…" + f"({len(v)} chars)"


def mask_email(addr):
    local, _, domain = addr.partition("@")
    return (local[:1] + "***@" + domain) if local else "***@" + domain


def redact(text):
    """Mask credentials, e-mail addresses and home-folder user names in any evidence text, whichever check shows it
    (a snippet shown for one rule can contain data that another rule protects)."""
    if not text:
        return text
    for name, rx, grp, *_ in SECRET_RULES:

        def sub(m, grp=grp, name=name):
            if name == "Private key":
                return "[PRIVATE KEY]"
            g = grp or next((i for i, v in enumerate(m.groups(), 1) if v), 0)
            val = m.group(g) if g else m.group(0)
            if not val or PLACEHOLDER.match(val):
                return m.group(0)
            a, b = m.span(g) if g else m.span(0)
            return m.group(0)[: a - m.start()] + mask_secret(val) + m.group(0)[b - m.start() :]

        text = rx.sub(sub, text)
    text = EMAIL.sub(lambda m: m.group(0) if EMAIL_IGNORE.search(m.group(0)) else mask_email(m.group(0)), text)
    return USER_PATH.sub(
        lambda m: (
            m.group(0) if USER_IGNORE.match(m.group(1)) else m.group(0)[: -len(m.group(1))] + m.group(1)[:1] + "***"
        ),
        text,
    )


SECRET_RULES = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), None),
    ("Client secret", re.compile(r"(?i)\b(client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?([^\s\"'<>,;]{8,})"), 2),
    (
        "Password assignment",
        re.compile(r"(?i)\b(pass(?:word|wd)?|pwd)\b[\"']?\s*[:=]\s*[\"']([^\"'\s$<>{}]{4,})[\"']"),
        2,
    ),
    (
        "Password attribute / element",
        re.compile(r"(?i)\b(?:password|passwd)\s*=\s*\"([^\"$<>{}\s]{4,})\"|<(?:password|passwd)>([^<$\s{]{4,})</"),
        None,
    ),
    (
        "Password in configuration file",
        re.compile(
            r"(?im)^[ \t]*[\w.\-]*(?:password|passwd|pwd|secret|credentials?)[\w.\-]*[ \t]*[=:][ \t]*"
            r"([^\s$<>{}%\"']{4,})[ \t]*$"
        ),
        1,
        {".properties", ".ini", ".cfg", ".conf", ".env", ".prefs", ".toml", ""},
    ),
    (
        "Password in URL",
        re.compile(r"(?i)(?:jdbc:|https?://|ldaps?://)[^\s\"'<>]*?[:/?&;](?:password|pwd)=([^\s&\"'<>;]{4,})"),
        1,
    ),
    ("Credentials in URL", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@\"'<>]{1,64}:([^\s/@\"'<>]{4,})@[\w.-]+"), 1),
    ("Basic auth header", re.compile(r"(?i)authorization\s*[:=]\s*[\"']?basic\s+([A-Za-z0-9+/=]{12,})"), 1),
    (
        "API key / token",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\b[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-./+=]{16,})[\"']"
        ),
        2,
    ),
]

PLACEHOLDER = re.compile(
    r"(?i)^(\*+|x+|\.+|changeme|change_me|password|secret|your[_-]?\w*|example\w*|dummy|test|null|none|"
    r"true|false|<[^>]*>|\$\{.*|%\w+%|\{\{.*)$"
)

EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

EMAIL_IGNORE = re.compile(
    r"(?i)^(noreply|no-reply|donotreply|example|user|admin|info|contact|support|security|test|"
    r"foo|bar|name|someone|somebody|firstname\.lastname|first\.last|john\.doe|jane\.doe|"
    r"vorname\.nachname|max\.mustermann|prenom\.nom|jean\.dupont)@|"
    r"@(example\.(com|org|net)|[\w.-]+\.example|localhost|test|invalid|"
    r"users\.noreply\.github\.com|\d+x?\.(png|jpg|svg|gif))$"
)

USER_PATH = re.compile(
    r"(?i)(?:[a-z]:[\\/]+(?:users|documents and settings)[\\/]+|/home/|/Users/)([A-Za-z0-9][^\\/\s\"'<>:*()]{1,39})"
)

USER_IGNORE = re.compile(
    r"(?i)^(public|default|all users|shared|runner|user|username|<?\$?\{?user\w*\}?>?|%username%|me|"
    r"you|admin|root|ubuntu|jenkins|gitlab-runner|travis|build|vagrant|node|runneradmin|"
    r"circleci|appveyor|ec2-user|docker|nobody|guest|\.\.\.|xxx|john|jdoe|data|tmp|temp|work|workspace|git|src|"
    r"project|projects|dev|test|tests|home|opt|share|local|app|apps|server|workspaces?)$"
)
