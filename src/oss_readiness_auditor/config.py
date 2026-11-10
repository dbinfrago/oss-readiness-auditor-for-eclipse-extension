# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""Effective configuration: defaults < configuration file < command line."""

import copy
import hashlib
import os
import re
import tomllib

from .checks import ALL as CHECKS
from .common import glob_match
from .packs import PACKS

DEFAULT_CONFIG = {
    "project": {"name_patterns": None, "own_prefixes": None, "family_depth": 2, "vendors": [], "hosted_by": []},
    "scan": {"exclude": [], "products": [], "osv_db": []},
    "scenario": {"move_out": []},
    "packs": {"enable": [], "disable": []},
    "checks": {},  # [checks.<check id>]: enabled, level and the check's own OPTIONS – validated in check_tables()
    "rules": {
        "proprietary": [],
        "ownership": [],
        "public_hosts": [],
        "internal_host_hints": [],
        "namespace_allow": [],
        "bundle_to_maven": {},
        "data_files": [],
    },
    "suppress": [],
}

CONFIG_KEYS = {k: set(v) if isinstance(v, dict) and k != "checks" else None for k, v in DEFAULT_CONFIG.items()}

# How much a check's findings weigh; "default" leaves it to the check's own rules.
LEVELS = {
    "default": "the check's own rules decide",
    "blocker": "any finding blocks publication",
    "judgement": "findings need a person's judgement, but never block",
    "info": "findings are shown for information only (not assessed)",
}
CHECK_IDS = {m.ID: m for m in CHECKS}


def check_tables(tables, where):
    """Validate [checks.<id>] tables (from a configuration file or a rule pack)."""
    for cid, table in tables.items():
        if cid not in CHECK_IDS:
            raise ValueError(f"{where}: unknown check [checks.{cid}] (checks: {', '.join(CHECK_IDS)})")
        options = getattr(CHECK_IDS[cid], "OPTIONS", {})
        for key, value in table.items():
            if key == "enabled":
                ok, allowed = isinstance(value, bool), "true or false"
            elif key == "level":
                ok, allowed = value in LEVELS, ", ".join(f'"{x}"' for x in LEVELS)
            elif key in options:
                opt = options[key]
                default, choices = opt["default"], opt.get("choices")
                values = value if isinstance(default, list) else [value]
                ok = isinstance(value, type(default)) and (not choices or all(v in choices for v in values))
                allowed = (f"one of {choices}" if choices else type(default).__name__) + (
                    " (a list)" if isinstance(default, list) else ""
                )
            else:
                known = ["enabled", "level", *options]
                raise ValueError(f"{where}: unknown key '{key}' in [checks.{cid}] (keys: {', '.join(known)})")
            if not ok:
                raise ValueError(f"{where}: checks.{cid}.{key} = {value!r} – expected {allowed}")


class Config:
    """Effective configuration: defaults < config file < command line; inferred values where nothing is given.
    `source` records where each project fact came from, for the report."""

    def __init__(self, path=None, cli=None):
        self.path, self.sha256, self.base, self.text = None, None, os.getcwd(), None
        raw = {}
        if path:
            with open(path, "rb") as fh:
                blob = fh.read()
            self.path, self.sha256 = os.path.abspath(path), hashlib.sha256(blob).hexdigest()
            self.base = os.path.dirname(self.path)
            self.text = blob.decode("utf-8")
            raw = tomllib.loads(self.text)
            check_tables(raw.get("checks", {}), path)
            for k, v in raw.items():
                if k not in CONFIG_KEYS:
                    raise ValueError(f"{path}: unknown section [{k}]")
                if CONFIG_KEYS[k] is not None:
                    unknown = set(v) - CONFIG_KEYS[k]
                    if unknown:
                        raise ValueError(f"{path}: unknown key(s) in [{k}]: {', '.join(sorted(unknown))}")
        self.data = {
            k: (dict(copy.deepcopy(v), **raw.get(k, {})) if isinstance(v, dict) else list(raw.get(k, v)))
            for k, v in DEFAULT_CONFIG.items()
        }
        self.source = {
            "own_prefixes": "config file" if self.project["own_prefixes"] is not None else None,
            "name_patterns": "config file" if self.project["name_patterns"] is not None else None,
        }
        cli = cli or {}
        if cli.get("own_prefix"):
            self.project["own_prefixes"], self.source["own_prefixes"] = list(cli["own_prefix"]), "command line"
        if cli.get("name_pattern"):
            self.project["name_patterns"], self.source["name_patterns"] = list(cli["name_pattern"]), "command line"
        for p in cli.get("pack") or []:
            off = p.startswith(("-", "no-"))
            (self.packs["disable"] if off else self.packs["enable"]).append(re.sub(r"^(\+|-|no-)", "", p))
        self.products = [self._abs(p) for p in self.scan["products"]] + list(cli.get("product") or [])
        self.osv_db = [self._abs(p) for p in self.scan["osv_db"]] + list(cli.get("osv_db") or [])
        self.exclude = list(self.scan["exclude"]) + list(cli.get("exclude_path") or [])
        self.move_out = list(self.data["scenario"]["move_out"]) + list(cli.get("move_out") or [])
        self.anonymise = bool(cli.get("anonymise_path"))
        for p in self.packs["enable"] + self.packs["disable"]:
            if p not in PACKS:
                raise ValueError(f"unknown rule pack '{p}' (available: {', '.join(PACKS)})")
        self.active_packs = [
            p
            for p, d in PACKS.items()
            if (d["default"] or p in self.packs["enable"]) and (d.get("locked") or p not in self.packs["disable"])
        ]
        self.check_config = self._check_settings()
        self.suppressions = []
        for i, s in enumerate(self.data["suppress"]):
            if not s.get("check") or not s.get("reason"):
                raise ValueError(f"[[suppress]] #{i + 1}: 'check' and 'reason' are required")
            self.suppressions.append(
                {
                    "check": s["check"],
                    "path": s.get("path"),
                    "text": s.get("text"),
                    "rx": re.compile(s["text"]) if s.get("text") else None,
                    "reason": s["reason"],
                    "used": 0,
                }
            )

    def _check_settings(self):
        """Effective settings of every check: defaults < active rule packs (in pack order) < configuration file.
        Returns {check id: {key: (value, source)}}."""
        out = {}
        for m in CHECKS:
            s = {"enabled": (True, "default"), "level": ("default", "default")}
            s |= {k: (copy.deepcopy(o["default"]), "default") for k, o in getattr(m, "OPTIONS", {}).items()}
            out[m.ID] = s
        layers = [(f"pack {p}", PACKS[p].get("checks", {})) for p in self.active_packs]
        layers.append(("configuration file", self.data["checks"]))
        for source, tables in layers:
            check_tables(tables, source)
            for cid, table in tables.items():
                for k, v in table.items():
                    out[cid][k] = (v, source)
        return out

    def check_option(self, cid, key):
        return self.check_config[cid][key][0]

    def check_overrides(self):
        """Settings that differ from the defaults, for the report: [{check, key, value, source}]."""
        return [
            {"check": cid, "key": k, "value": v, "source": src}
            for cid, s in self.check_config.items()
            for k, (v, src) in s.items()
            if src != "default"
        ]

    def __getattr__(self, name):
        data = self.__dict__.get("data")
        if data is not None and name in data:
            return data[name]
        raise AttributeError(name)

    def _abs(self, p):
        return p if os.path.isabs(p) else os.path.normpath(os.path.join(self.base, p))

    def pack_values(self, key, extra=None):
        """Values of `key` from all active packs, plus configured extras."""
        out = []
        for p in self.active_packs:
            v = PACKS[p].get(key)
            if v:
                out += v if isinstance(v, list) else [v]
        return out + list(self.rules.get(extra or key, []) if extra is not False else [])

    def pack_mapping(self, key):
        """Tables of `key` from all active packs, then the configured table (later entries win)."""
        out = {}
        for p in self.active_packs:
            out.update(PACKS[p].get(key) or {})
        return out | dict(self.rules.get(key) or {})

    def suppressed(self, check, file, text):
        for s in self.suppressions:
            if (
                s["check"] in (check, "*")
                and (not s["path"] or glob_match(file, s["path"]))
                and (not s["rx"] or s["rx"].search(text or ""))
            ):
                s["used"] += 1
                return s
        return None

    def summary(self):
        anon = getattr(self, "anonymise", False)
        return {
            "file": (os.path.basename(self.path) if anon else self.path) if self.path else None,
            "text": self.text,
            "sha256": self.sha256,
            "packs": self.active_packs,
            "own_prefixes": self.project["own_prefixes"],
            "own_prefixes_source": self.source["own_prefixes"],
            "name_patterns": self.project["name_patterns"],
            "name_patterns_source": self.source["name_patterns"],
            "family_depth": self.project["family_depth"],
            "vendors": self.project["vendors"],
            "hosted_by": self.project["hosted_by"],
            "exclude": self.exclude,
            "move_out": self.move_out,
            "checks": self.check_overrides(),
            "rules": {k: v for k, v in self.rules.items() if v},
            "suppress": [{k: s[k] for k in ("check", "path", "text", "reason", "used")} for s in self.suppressions],
        }
