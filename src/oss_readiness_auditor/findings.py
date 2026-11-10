# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""The check framework: a check, its findings, evidence, rules and per-component counts."""

from collections import Counter

from .common import MAX_EVIDENCE
from .masking import redact

STATUS = ("blocker", "judgement", "clear", "not_run", "info")


class Check:
    """The result of one check: status, key figure, finding text, tables and evidence. Findings are recorded with
    add(), which applies the acknowledgements (suppressions) of the configuration and counts every finding against
    the unit (bundle, module) that contains its file."""

    def __init__(self, ctx, cid, group, title, icon, blocks, resolve=""):
        self.ctx = ctx
        self.id, self.group, self.title, self.icon, self.blocks = cid, group, title, icon, blocks
        self.status = "clear"
        self.figure = "0"
        self.figure_label = ""
        self.finding = ""
        self.tables = []  # [{caption, columns, rows, note}]
        self.evidence = []  # [{file, line, text, tag}]
        self.evidence_total = 0
        self.rules = []  # human-readable description of every rule used
        self.by_component = Counter()  # unit id -> number of findings (complete)
        self.by_component_b = Counter()  # unit id -> number of blocker-level findings
        self.shared = []  # [units, blocker-level] of findings that apply to several units
        self.suppressed = []  # [{file, line, text, tag, reason}] acknowledged in the configuration
        self.resolve = resolve  # what resolves the findings, in plain words

    def add(self, file, line=None, text="", tag="", where=None, issue=True, level=None, match=None):
        """Record a finding; returns False if the configuration acknowledges (suppresses) it.
        `where`: paths/sources it applies to (default: `file`); each unit counts once.
        `issue=False`: informational evidence (e.g. a file that is present), not counted against units.
        `level="judgement"`: a candidate that does not by itself block (e.g. a medium advisory, a public host).
        `match`: text that suppression patterns are matched against (default: `text`; masked values are not
        matched, so a suppression of a secret names its file and line context instead)."""
        if issue:
            s = self.ctx.config.suppressed(self.id, file, match if match is not None else f"{tag} {text}")
            if s:
                self.suppressed.append({"file": file, "line": line, "text": text, "tag": tag, "reason": s["reason"]})
                return False
        text = redact(text)
        comps = sorted({self.ctx.components.resolve(w) for w in (where or [file])})
        if issue:
            for cid in comps:
                self.by_component[cid] += 1
                if level != "judgement":
                    self.by_component_b[cid] += 1
            if len(comps) > 1:
                self.shared.append([comps, level != "judgement"])
        self.evidence_total += 1
        if len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(
                {"file": file, "line": line, "text": text, "tag": tag, "components": comps, "issue": issue}
            )
        return True

    def apply_level(self, level):
        """Override how much the findings weigh (setting checks.<id>.level)."""
        if level == "blocker" and self.status == "judgement":
            self.status = "blocker"
            self.by_component_b = Counter(self.by_component)
            self.shared = [[units, True] for units, _ in self.shared]
        elif level == "judgement" and self.status == "blocker":
            self.status = "judgement"
        elif level == "info" and self.status in ("blocker", "judgement"):
            self.status = "info"

    def rule(self, name, detail):
        self.rules.append({"name": name, "detail": detail})

    def as_dict(self):
        return {
            k: getattr(self, k)
            for k in (
                "id",
                "group",
                "title",
                "icon",
                "blocks",
                "status",
                "figure",
                "figure_label",
                "finding",
                "resolve",
                "tables",
                "evidence",
                "evidence_total",
                "rules",
                "suppressed",
            )
        } | {
            "by_component": dict(self.by_component),
            "by_component_b": dict(self.by_component_b),
            "shared": self.shared,
        }


GROUPS = [
    {"id": "legal", "title": "Licensing & IP", "icon": "scale"},
    {"id": "security", "title": "Security & data", "icon": "shield-alert"},
    {"id": "project", "title": "Project basics & governance", "icon": "landmark"},
]
