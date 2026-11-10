<!--
SPDX-FileCopyrightText: 2026 DB InfraGO AG
SPDX-License-Identifier: Apache-2.0
-->

# OSS readiness auditor for Eclipse extensions

Offline check of a source tree for everything that blocks publishing it as open source. It is built for
Eclipse/OSGi/Tycho code bases, such as RCP applications and Papyrus, Sirius or Capella extensions. Most checks work on
any repository.

The result is **one static HTML page**. It needs no external resources and no server, and it stays readable with
JavaScript disabled. In this order:
1. **At a glance:** one line per check – why it matters, the key figure, the result.
2. **Details:** every check with its figures, what resolves it, and the evidence (file and line).
3. **Hotspots:** the units (bundles, modules) to start with – ranked by findings in blocker checks and by how many
   units depend on them.
4. **Method and rules:** the complete rule set of the run.
5. **Run:** configuration, inferred project facts and the data needed to reproduce the run.

Key properties:
- **Deterministic:** every finding comes from a documented rule (a regular expression or a file check). There is no AI and no scoring model.
- **Offline:** the tool never opens a network connection. Vulnerability data comes from database dumps that you download yourself.
- **Small and reviewable:** the analysis uses only the Python standard library; one check per module, built-in knowledge in plain TOML rule packs. The HTML report is rendered with Jinja (its only dependency). Python 3.11 or later; `git` is used if present.
- **One verifiable file if you want it:** `oss-readiness-audit.pyz` contains the tool and its pinned dependencies, runs on any Python 3.11+ with nothing installed, and is built reproducibly, so its SHA-256 can be checked.
- **Little configuration needed:** project facts are inferred from the repository, and the report states which values were inferred. An optional TOML file can override them.
- **Shareable output:** credentials and personal data are masked in the report.

## Install and run

**With [uv](https://docs.astral.sh/uv/)**, which brings a suitable Python along:

```sh
uv tool install .                     # from this folder, or from a wheel / sdist
oss-readiness-audit /path/to/repository -o report.html

uvx --from . oss-readiness-audit /path/to/repository -o report.html   # once, without installing
```

**As a single file**, e.g. on a machine without internet access: copy `oss-readiness-audit.pyz` (built by CI, or with
`uv run --frozen python scripts/build_pyz.py`) and its SHA-256, check the hash, and run it with any Python 3.11+:

```sh
shasum -a 256 oss-readiness-audit.pyz      # compare with the published SHA256SUMS
python3 oss-readiness-audit.pyz /path/to/repository -o report.html
```

**With pip:** `pip install .`, then `oss-readiness-audit …` or `python -m oss_readiness_auditor …`.

## Configuration

**No configuration is needed for a first run.** The tool infers what it needs to know about the project from what
the repository declares:

| Fact | Inferred from | Used by |
|---|---|---|
| Own name prefixes | `Bundle-SymbolicName` and feature ids (see below) | missing components, foreign namespaces, hotspots, product and committed jars |
| Product name | `name` of `.product` files and `<name>` of the root POM; without either, an acronym starting the `Bundle-Name`/`Bundle-Vendor` of most bundles (`XYZ Diagram Tools` → `XYZ`) | name check |
| Own model domains | own prefixes, reversed (`org.eclipse.sirius` → `eclipse.org/sirius`) | model namespaces |
| File extensions | the repository's files | personal data: `name@file.ext` is not an e-mail address |

**How the own prefixes are inferred:**
- Names are grouped by organisation root, e.g. `com.acme`.
- Within a group, the own prefix is the deepest prefix shared by at least 90 % of the names.
- Under roots shared by many projects (`org.eclipse`, `org.polarsys`, `org.apache`, …), grouping starts one segment deeper. So Papyrus gets `org.eclipse.papyrus`, not `org.eclipse`.
- In repositories with at least 20 names, a group with under 5 % of the names contributes only its exact names. These are typically fragments of someone else's bundles.

Review the inferred values in the report under **Run and reproducibility**. Then spawn a configuration for the audit:
it contains the inferred facts, the rule packs and **every check with its settings** (effective values as comments,
ready to uncomment):

```sh
oss-readiness-audit /path/to/repository --spawn-config > oss-readiness.toml               # add --pack openrail etc.
oss-readiness-audit /path/to/repository -c oss-readiness.toml -o report.html
oss-readiness-audit /path/to/repository -c oss-readiness.toml --spawn-config > new.toml   # refresh, keeping settings
```

Command-line options take precedence over the file, and the file takes precedence over inference. Unknown keys are an
error, so typos don't go unnoticed. [`examples/oss-readiness.toml`](examples/oss-readiness.toml) shows every key:

| Section | Keys |
|---|---|
| `[project]` | `own_prefixes`, `name_patterns`, `vendors` (accepted Bundle-Vendor values), `hosted_by` (foundations hosting the project, e.g. `["org.eclipse"]`) |
| `[scan]` | `exclude` (path globs not scanned), `products`, `osv_db` |
| `[packs]` | `enable`, `disable` (see below) |
| `[checks.<id>]` | per check: `enabled`, `level`, and its own settings (see below) |
| `[rules]` | additions: `proprietary`, `ownership`, `public_hosts`, `internal_host_hints`, `namespace_allow`, `bundle_to_maven` |
| `[scenario]` | `move_out` (see "Scenario" below) |
| `[[suppress]]` | `check`, `path`, `text`, `reason`: acknowledge a reviewed finding |

**Checks and their criticality (`[checks.<id>]`)** – every check (ids in [docs/METHODS.md](docs/METHODS.md)):

```toml
[checks.domain-data]
enabled = false                 # do not run this check
[checks.name-logo]
level = "info"                  # default | blocker | judgement | info
[checks.reuse-dco]
reuse = "blocker"               # check-specific settings; also: dco
[checks.project-basics]
required = ["LICENSE", "README", "SECURITY"]
[checks.openrail]
target_stage = 2                # with the openrail pack
```

`level` overrides how much a check's findings weigh: `default` (its own rules decide), `blocker` (any finding
blocks), `judgement` (never blocks), `info` (shown, not assessed). Rule packs can set defaults (the `openrail` pack
makes the stage 1 community files required); the configuration file overrides them. The report lists every
setting that differs from the defaults and where it comes from, and each affected check states its criticality in
its rules.

**Acknowledged findings (`[[suppress]]`)** stop counting, but they don't disappear:
- each check lists them, with the reason, under "Acknowledged in the configuration";
- the run section shows rules that matched nothing.

The configuration file's SHA-256 is part of the report. Pass the configuration explicitly with `-c`. The tool never
reads a configuration from the audited repository, so the audited party cannot silence its own findings.

### Rule packs

Built-in knowledge comes in packs, and the report lists the packs used:

| Pack | Default | Contents |
|---|---|---|
| `core` | always | Licenses, credentials, hosts, personal data, project files, REUSE/DCO |
| `eclipse` | on | MANIFEST.MF, plugin.xml, feature.xml, .product, .target, about.html, OSGi console / debug launch arguments, Eclipse Orbit bundle → Maven map, Eclipse ecosystem hosts |
| `emf` | on | Model namespaces (`nsURI`) under foreign domains |
| `lang-en`, `lang-fr`, `lang-de` | on (`lang-en` always) | Wording of proprietary, ownership and confidentiality notices in each language |
| `rail` | off | railML infrastructure data files (enables the "Real-world domain data" check) |
| `openrail` | off | [OpenRail Association](https://openrailassociation.org) project criteria: enables the "OpenRail project criteria" check and makes the stage 1 community files required |

Enable or disable packs with `--pack rail` or `--pack no-lang-de`, or under `[packs]` in the configuration. Domain data
rules of your own go in `[[rules.data_files]]` (`name`, `extensions`, `root`, `path`).

## What is checked

| Group | Check | Result if found |
|---|---|---|
| Licensing & IP | Proprietary license clauses (EN/FR/DE wording, holder named); "All rights reserved" without any license grant; missing LICENSE | Blocker |
| | Source files without a copyright holder (generated code reported separately) | Needs judgement |
| | References to missing components: classes in plugin.xml; bundles in Require-Bundle, Fragment-Host, feature.xml and .product; own packages in Import-Package; Maven modules | Needs judgement |
| | Eclipse vendor and license metadata: Bundle-Vendor / provider-name (with `%key` resolution), features without a license, bundles without about.html | Needs judgement |
| | Product name and logos (trademark rights): logo files, Eclipse branding images (splash, about image, window icons), where the name appears | Needs judgement: one decision per name and logo – permission or rename/replace |
| | Names and namespaces of another organisation: own bundle/package names under a foundation's root (`org.eclipse`, `org.polarsys`, `org.apache`, …) unless `project.hosted_by` says the project is hosted there; model namespaces under a foreign domain | Needs judgement |
| | Third-party components: npm licenses, Maven dependencies, target platform units, committed binaries; committed jars (also in zip archives) identified by name, version and license – patched or locally built copies of upstream bundles are marked, because their license may require publishing the source | Blocker for copyleft/unlicensed, otherwise judgement |
| Security & data | Known vulnerabilities (OSV, offline) and rule-based code/config review | Blocker on critical/high |
| | Credentials (passwords, client secrets, keys, tokens, `password=` in configuration files) | Blocker |
| | Internal infrastructure references (host names) | Blocker for internal-looking hosts |
| | Real-world domain data (only with a data pack, e.g. `rail`) | Needs judgement |
| | Personal data (e-mail addresses, user names in paths) | Blocker |
| | Ownership and confidentiality notices | Needs judgement |
| Project basics | LICENSE, README, CONTRIBUTING, SECURITY, code of conduct, maintainers, NOTICE | Blocker for missing required files |
| | License header on every file ([REUSE](https://reuse.software) standard) and commit sign-off (DCO) | Judgement by default; blocker by setting |
| | OpenRail project criteria (with the `openrail` pack): stage 1 Onboarded and stage 2 Qualified, as far as they can be checked offline – maintainers, code of conduct, OSI license, REUSE/DCO and their automation, security policy, pinned and updated dependencies, changelog, signed artifacts, governance, roadmap; the rest is listed for a person | Blocker for unmet criteria of the target stage |

Every check with findings also says **what resolves them**, in plain words, for readers who decide rather than fix.

Every check's criticality can be changed in the configuration (see above).

**Result values:**
- **Blocker found:** must be resolved before publication.
- **Needs judgement:** candidates for a person to assess.
- **Clear:** no rule matched.
- **Not run:** an input was missing, e.g. no OSV dump.
- **For information:** findings of a check whose `level` is set to `info` – shown, not assessed.

## Hotspots

Every finding is counted against the **unit** that contains its file: an OSGi bundle (`META-INF/MANIFEST.MF`) or a
module (`pom.xml`, `package.json`, …). The hotspot table ranks the units with findings in blocker checks, then by how
many units depend on them – through `Require-Bundle`, `Import-Package` (resolved to the exporting bundle),
`Fragment-Host` and Maven dependencies between modules of the repository. Checks that hit more than half of all units
(typically missing license headers) are left out of the ranking. The JSON output (`--json`) keeps the complete
per-unit counts and dependencies.

### Scenario: moving units out

`--move-out PATTERN` (repeatable; a glob on unit name or path) answers the question "what if these units are
not published?". The report lists:
- the remaining units that depend on them directly;
- the units affected further down the dependency chain;
- the affected tests;
- the features that mix moved and kept units;
- the findings that leave with the moved units.

## Options

| Option | Purpose |
|---|---|
| `-o report.html` | Output file |
| `-c FILE` | TOML configuration |
| `--spawn-config` | Print a configuration for this repository (inferred facts, packs, every check's settings), then exit |
| `--json` | Also write the findings as JSON |
| `--product DIR` | Unpacked product folder whose jars, including nested jars, are inventoried; repeatable |
| `--osv-db FILE` | OSV vulnerability dump; repeatable |
| `--own-prefix PREFIX` | Own name prefix; repeatable; replaces the inferred prefixes |
| `--name-pattern REGEX` | Product name pattern; repeatable; replaces the inferred pattern |
| `--pack [no-]PACK` | Enable an optional pack, or disable a default pack (`no-lang-de`) |
| `--exclude-path GLOB` | Don't scan these paths |
| `--move-out PATTERN` | Scenario (see above) |
| `--anonymise-path` | Show only the repository folder name |
| `--quiet` | No progress output |

### Vulnerability data (offline)

Download the public OSV dumps once and pass them with `--osv-db`:
- `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip`
- `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`

The report records each dump's SHA-256 and its newest entry.

## Limits

- **Rules find candidates.** They don't prove a problem exists, and they can miss whatever matches no rule. Read the "Method and rules" section before relying on a "Clear".
- **Notice wordings:** proprietary and confidentiality notices are recognised in English, French and German wording. Other languages or unusual wordings need `rules.proprietary` / `rules.ownership`.
- **Dependencies:** links that exist only through extension points, services or reflection are not counted (hotspot ranking, move-out scenario).
- **Vulnerabilities:**
  - These are published advisories, not an exploitability assessment.
  - Version ranges use a simplified Maven/semver comparison.
  - Repackaged bundles without Maven metadata are matched only if they appear in the built-in Orbit map or in `rules.bundle_to_maven`.
- **REUSE:** the tool estimates REUSE coverage; it is not a compliance verdict. Confirm with `reuse lint`.
- **Licenses:** licenses of Maven dependencies and target platform units can't be determined offline; they are listed for an SBOM.

## Reviewing the methods

Every check and every rule is meant to be read:

- **[`docs/METHODS.md`](docs/METHODS.md)** lists every check with why it matters, what resolves its findings and its
  complete rule set. It is generated from the code (`scripts/methods.py`), and a test fails when it is out of date.
- **One module per check** in [`src/oss_readiness_auditor/checks/`](src/oss_readiness_auditor/checks/). Each starts
  with its `ID`, `TITLE`, `WHY` and `RESOLVE`, then has one function `run(ctx, c)`. A check reads only the explicit
  context (repository, configuration, components, inventory); there is no hidden shared state.
- **Built-in knowledge is data:** the rule packs in [`src/oss_readiness_auditor/packs/`](src/oss_readiness_auditor/packs/)
  are TOML files (wordings, host lists, the Orbit bundle map). A rule change is a data diff.
- **The report is separate:** templates and assets in `src/oss_readiness_auditor/report/`; a methods review can skip it.

```
src/oss_readiness_auditor/
  cli.py  audit.py  context.py      command line; runs the checks; what a check may use
  config.py  infer.py  repo.py      configuration; inferred project facts; access to the audited repository
  findings.py  masking.py           a check's findings; masking of secrets and personal data
  common.py  headers.py             shared helpers; license headers, MANIFEST and NLS parsing
  components.py                     units and their internal dependency graph
  checks/                           one module per check (registry and order in checks/__init__.py)
  inventory/                        npm, Maven, built products, offline OSV matching
  packs/                            rule packs (TOML)
  report/                           HTML rendering: html.py, templates/, assets/
```

## Development

```sh
uv sync && uvx pre-commit install       # pre-commit: REUSE lint, ruff, unit tests
uv run python -m unittest discover -s tests
```

The tests build a synthetic Eclipse extension in a temporary folder and check every rule for what it must find and
what it must not, plus inference, configuration, determinism, escaping of hostile repository content in the report,
and that `docs/METHODS.md` is current. CI runs them on Python 3.11 and 3.13, builds the wheel and the single-file
`.pyz` with checksums, and audits this repository with the `.pyz`. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Security issues:** please report them privately via GitHub ("Security" → "Report a vulnerability"), not as a
public issue. In scope are especially leaks through the report (data that should be masked) and anything the audited
repository could inject into the report or the tool.

## License

Copyright 2026 DB InfraGO AG. Licensed under the [Apache License 2.0](LICENSE).

The icon shapes embedded in the report come from [Lucide](https://lucide.dev) (ISC); three of them (arrow-right,
search, server) derive from [Feather](https://feathericons.com) (MIT). The report is rendered with Jinja2 and
MarkupSafe (BSD-3-Clause, Pallets); the single-file build contains them unmodified, with their license files. License
texts of this repository are in [`LICENSES/`](LICENSES).

The criteria of the `openrail` pack are paraphrased from the
[OpenRail Project Handbook](https://projects.openrailassociation.org/docs/incubation/process/) (© OpenRail Association,
CC BY 4.0). This tool is not affiliated with or endorsed by the OpenRail Association.
