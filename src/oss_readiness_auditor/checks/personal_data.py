# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source

import re
from collections import Counter

from ..common import line_index, line_of
from ..masking import EMAIL, EMAIL_IGNORE, USER_IGNORE, USER_PATH, mask_email

ID = "personal-data"
GROUP = "security"
TITLE = "Personal data"
ICON = "user-x"
# Why the check matters for publication
WHY = "Personal data may only be published with consent (GDPR)."
# What resolves its findings, for readers who decide rather than fix
RESOLVE = "Remove personal data, or obtain consent (e.g. authors who want to be credited)."

# Name@x.ext references (e.g. icon@2x.png, Class@file.java) are no addresses: the last part is a file extension.
FILE_TLDS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "ico",
    "bmp",
    "java",
    "class",
    "jar",
    "xml",
    "xsd",
    "json",
    "yml",
    "yaml",
    "txt",
    "md",
    "html",
    "htm",
    "js",
    "ts",
    "css",
    "properties",
    "log",
    "csv",
    "pdf",
    "zip",
    "ecore",
    "uml",
    "xtend",
    "trace",
}


def run(ctx, c):
    repo = ctx.repo
    tlds = FILE_TLDS | repo.extensions
    c.rule(
        "E-mail addresses",
        "/" + EMAIL.pattern + "/ – role and example addresses, git@host remotes and "
        "name@file.ext references (ending in a file extension used in the repository) ignored; shown masked.",
    )
    c.rule(
        "User paths",
        "Home-folder paths C:\\Users\\<name>, /home/<name>, /Users/<name> – generic names ignored; shown masked.",
    )
    c.rule(
        "Names in paths",
        "Path segments of tracked files equal to a user name found above (names that occur in "
        "more than 1 % of all paths are ordinary words, not people).",
    )
    emails, users = Counter(), Counter()
    for f in repo.files:
        t = repo.text(f)
        if not t:
            continue
        starts = None
        for m in EMAIL.finditer(t):
            a = m.group(0)
            if EMAIL_IGNORE.search(a) or a.split("@")[0].lower() == "git" or a.rsplit(".", 1)[-1].lower() in tlds:
                continue
            starts = starts or line_index(t)
            if c.add(f, line_of(starts, m.start()), mask_email(a), "e-mail", match=a):
                emails[a.lower()] += 1
        for m in USER_PATH.finditer(t):
            u = m.group(1)
            if USER_IGNORE.match(u):
                continue
            starts = starts or line_index(t)
            if c.add(
                f, line_of(starts, m.start()), m.group(0)[: -len(u)] + u[:1] + "***", "user path", match=m.group(0)
            ):
                users[u] += 1
    path_hits = 0
    seg_count = Counter(seg for f in repo.files for seg in set(re.split(r"[/.]", f)))
    names = {u for u in users if seg_count[u] <= max(5, len(repo.files) // 100)}
    for f in repo.files:
        segs = set(re.split(r"[/.]", f))
        if segs & names:
            path_hits += c.add(f, None, "user name in file path", "name in path")
    c.figure = str(len(emails) + len(users))
    c.figure_label = "distinct e-mail addresses and user names"
    c.finding = (
        f"{len(emails)} distinct e-mail addresses ({sum(emails.values())} occurrences), {len(users)} distinct "
        f"user names in home-folder paths ({sum(users.values())} occurrences), {path_hits} file paths containing "
        "such a user name. Authorship credits may stay with consent; everything else should go."
    )
    c.status = "blocker" if emails or users else "clear"
    return c
