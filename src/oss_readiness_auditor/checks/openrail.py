# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""OpenRail Association project criteria, as far as they can be checked offline from the repository.

Source: OpenRail Project Handbook, incubation process (stages 1 Onboarded and 2 Qualified), © OpenRail Association,
CC BY 4.0 – criteria paraphrased; not affiliated with or endorsed by the OpenRail Association. Criteria that need a
person (scope, adoption, production use, …) are listed as such; stage 3 (Adopted) is out of scope. Only runs with
the rule pack 'openrail'."""

import os
import re
from collections import Counter

from .internal_hosts import LOCKFILES
from .reuse_dco import reuse_coverage

ID = "openrail"
GROUP = "project"
TITLE = "OpenRail project criteria"
ICON = "train-front"
PACK = "openrail"
# Why the check matters for publication
WHY = (
    "Projects hosted by the OpenRail Association must meet the criteria of their incubation stage; the stage "
    "applied for is the target."
)
# What resolves its findings, for readers who decide rather than fix
RESOLVE = (
    "Meet every unmet criterion of the target stage; criteria for a person are answered in the OpenRail "
    "questionnaire (https://projects.openrailassociation.org/docs/incubation/process/)."
)

# Settings of this check ([checks.openrail] in the configuration)
OPTIONS = {
    "target_stage": {
        "default": 1,
        "choices": [1, 2],
        "about": "stage applied for: 1 Onboarded, 2 Qualified; criteria of higher stages are shown for information",
    },
}

HANDBOOK = "https://projects.openrailassociation.org/docs/incubation/process/"
STAGES = {1: "Onboarded", 2: "Qualified"}
MET, NOT_MET, PERSON = "met", "not met", "needs a person"

CI_FILE = re.compile(
    r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.pre-commit-config\.ya?ml|Jenkinsfile|"
    r"azure-pipelines\.ya?ml|\.circleci/config\.ya?ml|bitbucket-pipelines\.ya?ml|\.woodpecker(\.ya?ml|/[^/]+))$"
)
# Phrases that identify the text of an OSI-approved license (LICENSE / COPYING files)
OSI_TEXTS = [
    ("Apache-2.0", r"Apache License,?\s+Version 2\.0"),
    ("MIT", r"Permission is hereby granted, free of charge"),
    ("BSD", r"Redistribution and use in source and binary forms"),
    ("EPL", r"Eclipse Public License"),
    ("MPL-2.0", r"Mozilla Public License,?\s+(Version|v\.?)\s*2\.0"),
    ("GPL/LGPL/AGPL", r"GNU (LESSER |LIBRARY |AFFERO )?GENERAL PUBLIC LICENSE"),
    ("ISC", r"Permission to use, copy, modify, and(/or)? distribute this software for any"),
    ("EUPL", r"European Union Public Licen[cs]e"),
    ("Unlicense", r"This is free and unencumbered software released into the public domain"),
]
# OSI-approved SPDX identifiers recognised as names of LICENSES/<id>.txt
OSI_SPDX = re.compile(
    r"^(Apache-2\.0|MIT|MIT-0|BSD-[23]-Clause|0BSD|EPL-[12]\.0|MPL-2\.0|L?GPL-[23]\.0(-only|-or-later)?|"
    r"LGPL-2\.1(-only|-or-later)?|AGPL-3\.0(-only|-or-later)?|ISC|EUPL-1\.[12]|Unlicense|BSL-1\.0|Zlib|"
    r"PostgreSQL|UPL-1\.0|CDDL-1\.0|Artistic-2\.0|OSL-3\.0)$"
)


def community_file(repo, pattern):
    """First file matching `pattern` (file name) in the root, .github/ or docs/."""
    rx = re.compile(pattern, re.I)
    for f in repo.files:
        if (f.count("/") == 0 or f.startswith((".github/", "docs/"))) and rx.match(os.path.basename(f)):
            return f
    return None


def readme_text(repo):
    f = community_file(repo, r"^README(\.\w+)?$")
    return f, (repo.text(f) or "") if f else ""


def ci_text(repo):
    return "\n".join(repo.text(f) or "" for f in repo.files if CI_FILE.search(f))


def heading(text, words):
    return re.search(r"(?im)^(#{1,4}\s*|=+\s*)(" + words + r")\b", text) is not None


# --- criteria: (stage, key, title, how it is decided, evaluator(repo, ctx) -> (result, detail, file), optional)


def osi_license(repo, ctx):
    found = []
    for f in repo.files:
        if f.count("/") == 0 and re.match(r"(?i)^(LICEN[CS]E|COPYING)([.-]\w+)?$", f):
            t = repo.text(f) or ""
            found += [(name, f) for name, rx in OSI_TEXTS if re.search(rx, t, re.I)]
    found += [
        (os.path.splitext(os.path.basename(f))[0], f)
        for f in repo.files
        if f.startswith("LICENSES/") and OSI_SPDX.match(os.path.splitext(os.path.basename(f))[0])
    ]
    if found:
        return MET, "recognised: " + ", ".join(sorted({n for n, _ in found})), found[0][1]
    if any(re.match(r"(?i)^(LICEN[CS]E|COPYING)", f) for f in repo.files if f.count("/") == 0):
        return PERSON, "a LICENSE file exists, but its text is not recognised as an OSI-approved license", None
    return NOT_MET, "no LICENSE file and no OSI-approved license text in LICENSES/", None


def openly_licensed(repo, ctx):
    lic, third = ctx.results.get("license-notices"), ctx.results.get("third-party")
    if lic is None:
        return PERSON, "the license check is disabled", None
    if lic.status == "blocker" and lic.figure != "0":
        return NOT_MET, f"{lic.figure} files with a proprietary clause (see the license check)", None
    if third is not None and third.status == "blocker":
        return NOT_MET, "third-party components with a copyleft or restricted license (see the third-party check)", None
    return MET, "no proprietary clauses; no restricted third-party licenses found", None


def maintainers(repo, ctx):
    f = community_file(repo, r"^(MAINTAINERS|CODEOWNERS|GOVERNANCE)(\.\w+)?$")
    if f:
        return MET, f, f
    readme, text = readme_text(repo)
    if heading(text, "maintainers?"):
        return MET, f"section 'Maintainers' in {readme}", readme
    return NOT_MET, "no MAINTAINERS / CODEOWNERS file and no 'Maintainers' section in the README", None


def code_of_conduct(repo, ctx):
    f = community_file(repo, r"^CODE[_-]OF[_-]CONDUCT(\.\w+)?$")
    if f and re.search(r"OpenRail", repo.text(f) or "", re.I):
        return MET, f, f
    if f:
        return NOT_MET, f"{f} does not adopt the OpenRail Association Code of Conduct", f
    return NOT_MET, "no CODE_OF_CONDUCT file", None


def description(repo, ctx):
    readme, text = readme_text(repo)
    if not readme:
        return NOT_MET, "no README", None
    return PERSON, f"{readme} ({len(text.split()):,} words); the description is assessed with the questionnaire", readme


def manual(detail):
    return lambda repo, ctx: (PERSON, detail, None)


def trademarks(repo, ctx):
    n = ctx.results.get("name-logo")
    extra = (
        f" The name and logo check lists {n.figure} logo/branding images and the product name occurrences." if n else ""
    )
    return PERSON, "intent to transfer project trademarks to the OpenRail Association." + extra, None


def reuse(repo, ctx):
    covered, total = reuse_coverage(repo)
    pct = 100.0 * covered / total if total else 100.0
    if covered == total:
        return MET, f"all {total:,} files declare their license (confirm with 'reuse lint')", None
    return NOT_MET, f"{pct:.0f} % of {total:,} files declare their license", None


def reuse_ci(repo, ctx):
    if re.search(r"reuse\s+lint|fsfe/reuse-(action|tool)|id:\s*reuse\b", ci_text(repo), re.I):
        return MET, "a CI or pre-commit configuration runs the REUSE linter", None
    return NOT_MET, "no CI or pre-commit configuration runs 'reuse lint'", None


def dco(repo, ctx):
    log = repo.git_log_bodies()
    if log is None:
        return PERSON, "no git history available", None
    signed = sum(1 for _, b in log if "Signed-off-by:" in b)
    return (MET if signed == len(log) else NOT_MET), f"{signed} of {len(log)} commits signed off", None


def dco_ci(repo, ctx):
    if ".github/dco.yml" in repo.files or re.search(r"\bdco\b|signed-off-by", ci_text(repo), re.I):
        return MET, "DCO configuration or a sign-off check in CI", None
    return NOT_MET, "no automatic DCO check (e.g. the DCO GitHub app with .github/dco.yml, or a CI job)", None


def security_policy(repo, ctx):
    f = community_file(repo, r"^SECURITY(\.\w+)?$")
    return (MET, f, f) if f else (NOT_MET, "no SECURITY.md", None)


def pinned(repo, ctx):
    locks = [f for f in repo.files if os.path.basename(f) in LOCKFILES]
    jvm = [f for f in repo.files if os.path.basename(f) in ("pom.xml", "build.gradle", "build.gradle.kts")]
    if jvm or any(f.endswith(".target") for f in repo.files):
        also = f"; lockfile(s) for the rest: {', '.join(locks[:3])}" if locks else ""
        return PERSON, "Maven/Gradle/Tycho build: check that all versions are fixed" + also, None
    if locks:
        return MET, "lockfile(s): " + ", ".join(locks[:5]), locks[0]
    if any(os.path.basename(f) in ("package.json", "pyproject.toml", "Cargo.toml", "go.mod") for f in repo.files):
        return NOT_MET, "dependency manifests without a lockfile", None
    return MET, "no dependency manifests", None


def updates(repo, ctx):
    names = (
        ".github/dependabot.yml",
        ".github/dependabot.yaml",
        "renovate.json",
        "renovate.json5",
        ".renovaterc",
        ".renovaterc.json",
        ".github/renovate.json",
        ".github/renovate.json5",
        ".gitlab/renovate.json",
    )
    f = next((x for x in names if x in repo.files), None)
    return (MET, f, f) if f else (NOT_MET, "no Dependabot or Renovate configuration", None)


def scorecard(repo, ctx):
    readme, text = readme_text(repo)
    if re.search(r"scorecard", text, re.I):
        return (
            PERSON,
            f"{readme} mentions an OpenSSF Scorecard; the score (≥ 5/10) and its date are checked online",
            readme,
        )
    return NOT_MET, "the README does not state an OpenSSF Scorecard score", None


def changelog(repo, ctx):
    f = community_file(repo, r"^(CHANGELOG|CHANGES|HISTORY|NEWS|RELEASE[_-]?NOTES)(\.\w+)?$")
    if f:
        return MET, f, f
    if re.search(r"generate_release_notes|release-please|semantic-release|changesets", ci_text(repo), re.I):
        return MET, "release notes are generated in CI", None
    return NOT_MET, "no CHANGELOG file and no generated release notes", None


def signed_artifacts(repo, ctx):
    if re.search(
        r"cosign|sigstore|attest-build-provenance|actions/attest|gpg\s+--(detach-)?sign|minisign", ci_text(repo), re.I
    ):
        return MET, "CI signs or attests release artifacts", None
    return NOT_MET, "no signing of release artifacts in CI (e.g. Sigstore/cosign, artifact attestations, GPG)", None


def sbom(repo, ctx):
    if re.search(r"cyclonedx|\bsbom\b|syft|spdx-sbom", ci_text(repo), re.I):
        return MET, "CI produces an SBOM", None
    return NOT_MET, "no SBOM for release artifacts (recommended)", None


def governance(repo, ctx):
    f = community_file(repo, r"^GOVERNANCE(\.\w+)?$")
    if f:
        return MET, f, f
    for g in (readme_text(repo)[0], community_file(repo, r"^CONTRIBUTING(\.\w+)?$")):
        if g and heading(repo.text(g) or "", "governance|decision[- ]making|becoming a (committer|maintainer)"):
            return MET, f"governance section in {g}", g
    return NOT_MET, "no GOVERNANCE file or governance section (how decisions are taken, how to become maintainer)", None


def roadmap(repo, ctx):
    f = community_file(repo, r"^ROADMAP(\.\w+)?$")
    if f:
        return MET, f, f
    readme, text = readme_text(repo)
    if heading(text, "roadmap"):
        return MET, f"section 'Roadmap' in {readme}", readme
    return NOT_MET, "no ROADMAP file or 'Roadmap' section", None


def contributors(repo, ctx):
    authors = repo.git_authors()
    if not authors:
        return PERSON, "no git history available", None
    domains = Counter(a.rsplit("@", 1)[-1] for a in authors)
    return (
        PERSON,
        (
            f"{len(set(authors))} commit authors, {len(authors):,} commits; e-mail domains: "
            + ", ".join(f"{d} ({n})" for d, n in domains.most_common(5))
        ),
        None,
    )


CRITERIA = [
    (
        1,
        "Scope",
        "Contributes to the challenges of the railway sector.",
        manual("assessed by the Technical Committee"),
        False,
    ),
    (
        1,
        "Description",
        "README present; the description itself is assessed with the questionnaire.",
        description,
        False,
    ),
    (
        1,
        "Maintainers",
        "MAINTAINERS / CODEOWNERS / GOVERNANCE file, or a 'Maintainers' section in the README.",
        maintainers,
        False,
    ),
    (
        1,
        "Code of conduct",
        "CODE_OF_CONDUCT file that adopts the OpenRail Association Code of Conduct (mentions OpenRail).",
        code_of_conduct,
        False,
    ),
    (
        1,
        "OSI-approved license",
        "LICENSE/COPYING text recognised as an OSI-approved license, or OSI-approved SPDX ids in LICENSES/.",
        osi_license,
        False,
    ),
    (
        1,
        "Only openly licensed code",
        "No proprietary clauses (license check) and no restricted third-party licenses (third-party check).",
        openly_licensed,
        False,
    ),
    (1, "Trademarks", "Intent to transfer the project's trademarks to the Association.", trademarks, False),
    (2, "REUSE compliant", "Every file declares its license (coverage estimate as in the REUSE check).", reuse, False),
    (2, "REUSE linter automated", "A CI or pre-commit configuration runs 'reuse lint'.", reuse_ci, False),
    (2, "DCO on all commits", "Every commit in the git history has a 'Signed-off-by:' line.", dco, False),
    (2, "DCO checked automatically", ".github/dco.yml (DCO app) or a CI job checking sign-offs.", dco_ci, False),
    (2, "Security policy", "SECURITY file in the root, .github/ or docs/.", security_policy, False),
    (
        2,
        "Dependencies pinned",
        "A dependency lockfile; with a Maven/Gradle/Tycho build a person confirms fixed versions.",
        pinned,
        False,
    ),
    (2, "Automated dependency updates", "Dependabot or Renovate configuration.", updates, False),
    (
        2,
        "OpenSSF Scorecard ≥ 5/10 in README",
        "The README states an OpenSSF Scorecard; the score itself is checked online.",
        scorecard,
        False,
    ),
    (2, "Changelog", "CHANGELOG/CHANGES/HISTORY/NEWS file, or release notes generated in CI.", changelog, False),
    (
        2,
        "Signed release artifacts",
        "CI signs or attests artifacts (Sigstore/cosign, artifact attestations, GPG, minisign).",
        signed_artifacts,
        False,
    ),
    (
        2,
        "SBOM for release artifacts",
        "CI produces an SBOM (CycloneDX, SPDX, Syft). Recommended, not required.",
        sbom,
        True,
    ),
    (
        2,
        "Open governance",
        "GOVERNANCE file, or a governance section in the README or CONTRIBUTING file.",
        governance,
        False,
    ),
    (2, "Public roadmap", "ROADMAP file or a 'Roadmap' section in the README.", roadmap, False),
    (
        2,
        "Healthy contributor base",
        "Assessed by the Technical Committee; commit authors and their e-mail domains are listed.",
        contributors,
        False,
    ),
    (2, "Used in production", "Assessed with the questionnaire.", manual("assessed with the questionnaire"), False),
    (
        2,
        "Specification reference implementation",
        "Only for specifications: a public reference implementation.",
        manual("only applies to specifications"),
        False,
    ),
]


def run(ctx, c):
    if "openrail" not in ctx.config.active_packs:
        return None
    repo = ctx.repo
    target = ctx.config.check_option(ID, "target_stage")
    c.rule(
        "Source",
        f"OpenRail Project Handbook, incubation process (© OpenRail Association, CC BY 4.0), paraphrased: {HANDBOOK}. "
        "Not affiliated with or endorsed by the OpenRail Association. Stage 3 (Adopted) is out of scope.",
    )
    c.rule(
        "Target stage",
        f"Criteria up to the target stage (setting checks.openrail.target_stage, here {target}) count: unmet "
        "criteria block, criteria for a person need judgement. Criteria of higher stages are shown for information.",
    )
    for stage, name, how, _, optional in CRITERIA:
        c.rule(f"Stage {stage} · {name}", how + (" Recommended: needs judgement when unmet." if optional else ""))
    rows, counts, blocking = [], Counter(), 0
    for stage, name, _, evaluate, optional in CRITERIA:
        result, detail, file = evaluate(repo, ctx)
        rows.append([f"{stage} {STAGES[stage]}", name, result, detail])
        if stage > target:
            continue
        counts[result] += 1
        if result == MET:
            c.add(file or "(repository root)", None, f"Stage {stage}: {name} – {detail}", "met", issue=False)
            continue
        blocks = result == NOT_MET and not optional
        tag = "not met" if result == NOT_MET else "needs a person"
        text = f"Stage {stage}: {name} – {detail}"
        if c.add(file or "(repository root)", None, text, tag, level=None if blocks else "judgement") and blocks:
            blocking += 1
    n = sum(counts[k] for k in (MET, NOT_MET, PERSON))
    c.figure = f"{counts[MET]}/{n}"
    c.figure_label = f"criteria of OpenRail stage {target} ({STAGES[target]}) met – {counts[PERSON]} need a person"
    c.finding = (
        f"Target: stage {target} ({STAGES[target]}). {counts[MET]} criteria met, {counts[NOT_MET]} not met, "
        f"{counts[PERSON]} for a person to assess (OpenRail questionnaire). Stage 3 (Adopted) is not assessed."
    )
    c.tables.append(
        {
            "caption": "OpenRail criteria",
            "columns": ["Stage", "Criterion", "Result", "Basis"],
            "rows": rows,
            "note": f"Handbook: {HANDBOOK}",
        }
    )
    c.status = "blocker" if blocking else ("judgement" if c.evidence_total > counts[MET] else "clear")
    return c
