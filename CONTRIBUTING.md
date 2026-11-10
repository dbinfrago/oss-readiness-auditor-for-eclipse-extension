<!--
SPDX-FileCopyrightText: 2026 DB InfraGO AG
SPDX-License-Identifier: Apache-2.0
-->

# Contributing

Issues and pull requests are welcome. Please be respectful and constructive.

```sh
uv sync && uvx pre-commit install   # then every commit runs REUSE lint, ruff and the tests
```

**Ground rules**

- **No project-specific knowledge in the tool.** Values that only fit one code base belong in its configuration.
  Knowledge true for an ecosystem or domain goes into a rule pack (`src/oss_readiness_auditor/packs/*.toml`).
- **Every finding comes from a documented rule** (`c.rule(...)`); the analysis stays offline, deterministic and
  standard-library only. Jinja is used by the report layer only, and repository content is never marked safe there.
- **A rule change comes with a test** in `tests/` (what it must find and what it must not), the regenerated
  `docs/METHODS.md` (`uv run --frozen python scripts/methods.py`), and a run on two public Eclipse projects it was not
  written for (e.g. Sirius, Capella) – mention new or vanished findings in the pull request.
- **A new check** is a module in `src/oss_readiness_auditor/checks/` (`ID`, `GROUP`, `TITLE`, `ICON`, `WHY`,
  `RESOLVE`, `run(ctx, c)`; optionally `OPTIONS` for its settings and `PACK`), registered in `checks/__init__.py`.
  Settings are read with `ctx.config.check_option(ID, key)`; `enabled` and `level` are handled for every check.
- **Versions:** a change in what a rule finds is at least a minor version, because reports change.
- **Sign off your commits** (`git commit -s`, [DCO](https://developercertificate.org)); new files carry an SPDX header.
