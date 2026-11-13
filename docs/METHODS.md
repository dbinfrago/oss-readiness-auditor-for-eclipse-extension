<!--
SPDX-FileCopyrightText: 2026 DB InfraGO AG
SPDX-License-Identifier: Apache-2.0
-->

# Methods of the OSS readiness auditor for Eclipse extensions

Generated from the code by `scripts/methods.py` – do not edit. Every check is one module in
`src/oss_readiness_auditor/checks/`; built-in knowledge is in the rule packs in `src/oss_readiness_auditor/packs/`.
The rules below are those of the default configuration with all rule packs enabled; a report lists the rules
of its own run. Every check can be configured in `[checks.<id>]`: `enabled`, `level` (how much its findings
weigh) and its own settings; `--spawn-config` writes all of them with their effective values.

**Levels:** `default` – the check's own rules decide; `blocker` – any finding blocks publication; `judgement` – findings need a person's judgement, but never block; `info` – findings are shown for information only (not assessed).

## Rule packs

| Pack | Default | Contents |
|---|---|---|
| `core` | always | Generic open-source hygiene: licenses, credentials, hosts, personal data, project files. |
| `eclipse` | on | Eclipse/OSGi/Tycho conventions: MANIFEST.MF, plugin.xml, feature.xml, .product, about.html, launch arguments, Orbit bundle names. |
| `emf` | on | EMF/Xtext/UML modelling: model namespaces (nsURI) under foreign domains. |
| `lang-en` | always | English wording of proprietary, ownership and confidentiality notices. |
| `lang-fr` | on | French wording of proprietary, ownership and confidentiality notices; French environment names (recette) as internal host hints. |
| `lang-de` | on | German wording of proprietary, ownership and confidentiality notices. |
| `rail` | off | Railway domain: railML infrastructure data files. |
| `openrail` | off | OpenRail Association project criteria (stage 1 Onboarded, stage 2 Qualified): adds the OpenRail check and makes the stage 1 community files required. |

## Checks

- [Proprietary license notices](#license-notices) – `license-notices`, Licensing & IP
- [Source files without an owner](#ownerless) – `ownerless`, Licensing & IP
- [References to missing components](#remnants) – `remnants`, Licensing & IP
- [Eclipse vendor and license metadata](#eclipse-metadata) – `eclipse-metadata`, Licensing & IP
- [Product name and logos (trademark rights)](#name-logo) – `name-logo`, Licensing & IP
- [Names and namespaces of another organisation](#namespace) – `namespace`, Licensing & IP
- [Third-party components and licenses](#third-party) – `third-party`, Licensing & IP
- [Known vulnerabilities](#vulnerabilities) – `vulnerabilities`, Security & data
- [Credentials in the repository](#secrets) – `secrets`, Security & data
- [Internal infrastructure references](#internal-hosts) – `internal-hosts`, Security & data
- [Real-world domain data](#domain-data) – `domain-data`, Security & data
- [Personal data](#personal-data) – `personal-data`, Security & data
- [Ownership and confidentiality notices](#ownership) – `ownership`, Security & data
- [Project basics and governance](#project-basics) – `project-basics`, Project basics & governance
- [License header on every file (REUSE standard) and commit sign-off (DCO)](#reuse-dco) – `reuse-dco`, Project basics & governance
- [OpenRail project criteria](#openrail) – `openrail`, Project basics & governance

<a id="license-notices"></a>

### Proprietary license notices

Source: [`src/oss_readiness_auditor/checks/license_notices.py`](../src/oss_readiness_auditor/checks/license_notices.py)

**Why it matters:** No license, no open source – nobody may legally use, change or share the code.

**To resolve:** The owners named in the clauses agree to the open-source license; the clauses are replaced by that license's header – also in code templates and generator settings, so new files stay clean.

**Settings** (`[checks.license-notices]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Proprietary clause:** Any of these patterns (packs: core, eclipse, emf, lang-en, lang-fr, lang-de, rail, openrail; named group 'holder' = owner) in the license header of a file – for code everything before the first package/import statement, otherwise the first 6000 characters, comment markers, markup and line breaks removed: /\\b(?:is|are|remains?|being)\\s+(?:the\\s+)?(?:sole\\s+|exclusive\\s+)?(?:intellectual\\s+)?property\\s+of\\s+(?:the\\s+)?(?P\<holder>(?-i:\[A-Z\\u00C0-\\u00DE0-9\])\[^,.;:()\\n\]{1,79}?)\\s\*(?:\[,.;:(\]|\\s+(?:and\\s+)?(?:their|its)\\s+use\\b|\\s+and\\s+(?:is|are|may)\\b)/ | /\\bproprietary\\s+(?:and\\s+confidential\\s+)?(?:information|software|source\\s+code|product|material)\\s+of\\s+(?:the\\s+)?(?P\<holder>(?-i:\[A-Z\\u00C0-\\u00DE0-9\])\[^,.;:()\\n\]{1,79}?)\\s\*(?:\[,.;:(\]|\$)/ | /\\b(?:confidential\\s+and\\s+proprietary|proprietary\\s+and\\s+confidential)\\b/ | /\\bunauthori\[sz\]ed\\s+(?:copying|use|reproduction|distribution|disclosure)\\b\[^.\]{0,80}?\\b(?:prohibited|forbidden)/ | /\\buse\\s+is\\s+subject\\s+to\\s+(?:a\\s+)?(?:specific|separate|written|prior)\\s+(?:license\\s+)?agreements?\\b/ | /\\b(?:est|sont|reste|restent|demeure|demeurent)\\s+(?:la\\s+)?(?:pleine\\s+)?(?:et\\s+enti\[èe\]re\\s+)?propri\[ée\]t\[ée\]\\s+(?:exclusive\\s+)?(?:du|de\\s+la|des|de|d\['’\])\\s\*(?P\<holder>(?-i:\[A-Z\\u00C0-\\u00DE0-9\])\[^,.;:()\\n\]{1,59}?)\\s\*\[,.;:(\]/ | /\\b(?:son|leur)\\s+utilisation\\s+est\\s+soumise\\s+\[àa\]\\s+(?:un\\s+)?accord/ | /\\btoute\\s+(?:reproduction|diffusion|copie)\\b\[^.\]{0,80}?\\binterdite/ | /\\b(?:ist|sind|bleibt|bleiben)\\s+(?:das\\s+)?(?:alleinige\\s+|ausschlie(?:ß|ss)liche\\s+)?(?:geistige\\s+)?Eigentum\\s+(?:der|des|von)\\s+(?P\<holder>(?-i:\[A-Z\\u00C0-\\u00DE0-9\])\[^,.;:()\\n\]{1,59}?)\\s\*\[,.;:(\]/ | /\\bunerlaubte\\s+(?:Vervielf\[äa\]ltigung|Weitergabe|Nutzung)\\b/
- **Searched in full:** Documentation (.adoc, .asciidoc, .bs, .htm, .html, .markdown, .md, .mediawiki, .rst, .tex, .textile, .txt, .xhtml) and Eclipse metadata that carries license and branding text: about.\*, feature.xml/.properties, plugin.properties, bundle.properties, \*.product, \*.genmodel, .settings/\*.prefs (code templates), license/notice files.
- **All rights reserved:** /\\ball\\s+rights\\s+reserved\\b|\\btous\\s+droits\\s+r\[ée\]serv\[ée\]s\\b|\\balle\\s+Rechte\\s+vorbehalten\\b/ in the header of a file whose header grants no license (no SPDX-License-Identifier and no license text such as EPL, Apache, MIT, BSD, GPL, MPL).
- **Licensed:** A header with an SPDX-License-Identifier or a recognised license grant: /(?i)SPDX-License-Identifier|made\\s+available\\s+under\\s+the\\s+terms\\s+of|Eclipse\\s+Public\\s+License|Licensed\\s+under\\s+the\\s+Apache\\s+License|Licensed\\s+to\\s+the\\s+Apache\\s+Software\\s+Foundation|Permission\\s+is\\s+hereby\\s+granted|GNU\\s+(?:Lesser\\s+|Library\\s+|Affero\\s+)?General\\s+Public\\s+License|Mozilla\\s+Public\\s+License|Redistribution\\s+and\\s+use\\s+in\\s+source\\s+and\\s+binary\\s+forms|Common\\s+Public\\s+License|Eclipse\\s+Distribution\\s+License|Creative\\s+Commons|This\\s+(?:program|file|library|software)\\s+is\\s+free\\s+software|(?:provided|licen\[sc\]ed|released|distributed|available)\\s+under\\s+(?:the\\s+)?(?:terms\\s+of\\s+(?:the\\s+)?)?(?:EPL|EDL|ASL|Apache|MIT|BSD|L?GPL|AGPL|MPL|CDDL|ISC|Unlicense|CC0|Eclipse)\\b/.
- **Code templates:** Eclipse code templates (.settings/\*.prefs) and EMF .genmodel 'copyrightText' write their text into every newly generated file; a proprietary clause there is reported as 'code template'.

<a id="ownerless"></a>

### Source files without an owner

Source: [`src/oss_readiness_auditor/checks/ownerless.py`](../src/oss_readiness_auditor/checks/ownerless.py)

**Why it matters:** Files without a known copyright holder cannot be relicensed by anyone.

**To resolve:** Establish who wrote these files (history, contracts) and add their copyright line, or document that a contributor agreement covers them.

**Settings** (`[checks.ownerless]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **No owner:** Source files (.c, .cpp, .groovy, .h, .java, .js, .jsx, .kt, .py, .scala, .ts, .tsx, .xtend) whose first 40 lines contain neither 'Copyright', '©' nor 'SPDX-FileCopyrightText', and that have no REUSE side-car file (\<file>.license) naming a copyright holder.
- **Generated code:** Reported separately, because their header comes from the generator (e.g. the genmodel copyrightText): files in src-gen/, xtend-gen/, gen/, generated/ folders, and files marked as generated (@generated / @Generated, 'Generated by', 'DO NOT EDIT', EMF begin-user-doc tags).

<a id="remnants"></a>

### References to missing components

Source: [`src/oss_readiness_auditor/checks/remnants.py`](../src/oss_readiness_auditor/checks/remnants.py)

**Why it matters:** The public code must build and run without parts that were removed.

**To resolve:** Restore the missing parts, remove the references, or confirm that the build generates them.

**Settings** (`[checks.remnants]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Own names:** A name is the project's own if it starts with one of the repository's own name prefixes. They are not built into the tool: they are inferred from the repository's bundle names or configured for the run (see "Run and reproducibility").
- **Missing classes:** plugin.xml/fragment.xml attributes class/defaultHandler/contributorClass/handler/launcher/delegate naming a class with an own name or in a package of the repository, without a .java/.xtend/.kt/.groovy/.scala source of that class in the repository. Names following EMF/Xtext generator conventions are tagged 'maybe generated'.
- **Missing bundles and features:** Own names in Require-Bundle, Fragment-Host, feature.xml \<plugin>/\<includes>/\<import>, and .product \<plugin>/\<feature> entries, without a bundle or feature of that name in the repository (X.source is accepted when X exists: Tycho generates it).
- **Missing packages:** Own packages in Import-Package (not resolution:=optional) that no bundle of the repository exports.
- **Missing modules:** \<module> entries in pom.xml whose folder does not exist.

<a id="eclipse-metadata"></a>

### Eclipse vendor and license metadata

Source: [`src/oss_readiness_auditor/checks/eclipse_metadata.py`](../src/oss_readiness_auditor/checks/eclipse_metadata.py)

**Why it matters:** Eclipse shows vendor, copyright and license of every installed feature and bundle to the user.

**To resolve:** Name the publishing organisation or project as vendor, give every feature a license and every bundle an about.html.

**Settings** (`[checks.eclipse-metadata]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Vendors:** Bundle-Vendor (MANIFEST.MF) and provider-name (feature.xml), %keys resolved from the Bundle-Localization file (default OSGI-INF/l10n/bundle.properties), plugin.properties and feature.properties. Vendors other than the accepted ones (project.vendors: none configured) are listed.
- **Feature license:** feature.xml without a \<license> element, or with an empty one: the update manager shows no license to the user.
- **about.html:** Bundles without an about.html (the Eclipse convention for the license of a plug-in; required by the Eclipse Foundation, recommended elsewhere).

<a id="name-logo"></a>

### Product name and logos (trademark rights)

Source: [`src/oss_readiness_auditor/checks/name_logo.py`](../src/oss_readiness_auditor/checks/name_logo.py)

**Why it matters:** Publishing under a name or with a logo needs the right to use them – the project's own as well as those of partners and third parties.

**To resolve:** A decision per name and logo: either the owner confirms in writing that the open-source project may use it (ideally with a trademark policy), or it is renamed or replaced before publication. Partner and third-party logos need their owner's permission or are removed. The occurrences below show how much a rename would touch.

**Settings** (`[checks.name-logo]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Logos:** Image files whose name contains 'logo'; images an Eclipse product shows as its identity (splash screen, about-dialog image, window icons – from .product files and the org.eclipse.core.runtime.products extension).
- **Product name:** Occurrences of the product name patterns in text files (case-sensitive). The patterns are not built into the tool: they are inferred from the name of .product files and the root POM, or configured for the run (see "Run and reproducibility"). Occurrences in product branding files (about.\*, \*.product, plugin/feature/bundle.properties, plugin\_customization.ini) are what users see as the product's identity.

<a id="namespace"></a>

### Names and namespaces of another organisation

Source: [`src/oss_readiness_auditor/checks/namespace.py`](../src/oss_readiness_auditor/checks/namespace.py)

**Why it matters:** Bundle and package names or model namespaces under another organisation's domain claim names – and often a trademark – that are not yours.

**To resolve:** Confirm the project is hosted by that organisation (setting project.hosted_by), or move bundles, packages and model namespaces to a domain the project controls (existing models need a migration), or obtain the owner's agreement.

**Settings** (`[checks.namespace]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Foundation namespaces:** An own name prefix (see "Run and reproducibility") under a name root that belongs to a foundation (org.eclipse: Eclipse Foundation, org.polarsys: Eclipse Foundation (PolarSys), org.osgi: OSGi Working Group (Eclipse Foundation), jakarta: Eclipse Foundation (Jakarta EE), org.apache: Apache Software Foundation, org.ow2: OW2, org.jenkins-ci: Jenkins project (Continuous Delivery Foundation)) claims the foundation's namespace, and often its trademark. Needs judgement unless the project is hosted there (setting project.hosted\_by, not set).
- **Defined namespaces:** nsURI="…" attributes in .ecore, .genmodel, .uml, .xcore and .profile.uml files (package definitions).
- **Own domains:** The repository's own name prefixes (see "Run and reproducibility"), reversed: org.example.tool -> example.org/tool. A namespace is the project's own if its host is the domain or a subdomain and, for a deeper prefix, its path starts with the next name segment.
- **Foreign:** A namespace with a registered-looking host (a dot and a top-level domain) that is not the project's own, not reserved for examples (example.com, \*.test, …). Reversed names as host (http://org.example.model) are foreign unless they start with an own prefix. URNs and hostless URIs (http:///…) are neutral.

<a id="third-party"></a>

### Third-party components and licenses

Source: [`src/oss_readiness_auditor/checks/third_party.py`](../src/oss_readiness_auditor/checks/third_party.py)

**Why it matters:** Every bundled component needs a compatible license and must be named in the notices.

**To resolve:** A bill of materials (SBOM) with the license of every bundled component; incompatible components are replaced or removed, the others named in the NOTICE file.

**Settings** (`[checks.third-party]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **npm licenses:** 'license' field of every non-dev package in package-lock.json. Blocker: GPL/AGPL/SSPL/BUSL/non-commercial or UNLICENSED (except the project's own private package). Missing field: needs judgement.
- **Maven dependencies:** \<dependency> entries of the repository's pom.xml files that are not the project's own group. Their license cannot be determined offline; they are listed for the SBOM.
- **Target platforms:** Eclipse .target files: \<unit> and Maven \<dependency> entries per p2/Maven location – the third-party bundles the product is built from; licenses are listed in the p2 metadata, not checked here.
- **Committed jars:** Jars tracked in the repository, and jars inside tracked zip archives, are identified from their MANIFEST.MF (Bundle-SymbolicName, Bundle-Version, Bundle-Name, Bundle-Vendor, Bundle-License; %keys from the jar's properties), META-INF/maven/\*\*/pom.properties, and – without Bundle-License – the license text in the jar's about.html or LICENSE/NOTICE file: 'own build' (own name), 'locally built upstream bundle' (someone else's bundle in a SNAPSHOT or development build – typically a patched copy, whose license may require publishing its source), 'third-party' or 'unidentified'. Identified versions are checked for known vulnerabilities.
- **Committed binaries:** Tracked files with extension .7z, .bin, .class, .dll, .dylib, .ear, .exe, .gz, .jar, .so, .tar, .war, .zip – their content and license cannot be reviewed from source (needs judgement).

<a id="vulnerabilities"></a>

### Known vulnerabilities

Source: [`src/oss_readiness_auditor/checks/vulnerabilities.py`](../src/oss_readiness_auditor/checks/vulnerabilities.py)

**Why it matters:** The first outside reader will run the same scan.

**To resolve:** Update affected components to a fixed version or document why an advisory does not apply; fix or justify each code finding.

**Settings** (`[checks.vulnerabilities]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Components:** npm: non-dev packages of every package-lock.json. Maven: direct \<dependency> entries of pom.xml files. Committed jars (also inside zip archives), identified the same way.
- **Advisories:** OSV.dev database dumps given with --osv-db, matched offline: exact version lists and ECOSYSTEM/SEMVER ranges (introduced / fixed / last\_affected). Severity: the advisory's own rating (GitHub: LOW/MODERATE/HIGH/CRITICAL). Advisories sharing a CVE/GHSA alias count once.
- **Code/config (high): Remote debugging enabled:** /-Xdebug\\b|-agentlib:jdwp|-Xrunjdwp/ – commented-out lines are skipped
- **Code/config (high): OSGi console opened (Eclipse launch argument):** /(?m)^\\s\*-console(?:\\s+\\S+)?\\s\*\$|\<programArgs>\[^\<\]\*(?\<!\[\\w-\])-console\\b|osgi\\.console\\s\*=\\s\*\\S|-Dosgi\\.console=\\S/ – commented-out lines are skipped
- **Code/config (high): Token or certificate validation disabled:** /(?i)setHostnameVerifier\\(\\s\*\\(?\[^)\]\*\\)?\\s\*->\\s\*true|TrustAllCerts|NoopHostnameVerifier|ALLOW\_ALL\_HOSTNAME\_VERIFIER|verify\\s\*=\\s\*False|rejectUnauthorized\\s\*:\\s\*false|NODE\_TLS\_REJECT\_UNAUTHORIZED\\s\*=\\s\*\['\\"\]?0/ – commented-out lines are skipped
- **Code/config (medium): SQL built by string concatenation:** /(?i)\\"\\s\*(?:CREATE|DROP|ALTER|GRANT)\\s+(?:DATABASE|SCHEMA|USER|ROLE|TABLE)\\b\[^\\"\]\*\\"\\s\*\\+|\\"\\s\*(?:SELECT|UPDATE|DELETE|INSERT)\\b\[^\\"\]\*(?:WHERE|VALUES|SET)\[^\\"\]\*\\"\\s\*\\+/ – commented-out lines are skipped
- **Code/config (medium): Secret printed to output:** /(?i)\\b(?:echo|printf|print|println|console\\.log|Write-Host)\\b\[^\\n\]\*\\\$\\{?\\w\*(?:PASS|PWD|SECRET|TOKEN)\\w\*/ – commented-out lines are skipped

<a id="secrets"></a>

### Credentials in the repository

Source: [`src/oss_readiness_auditor/checks/secrets.py`](../src/oss_readiness_auditor/checks/secrets.py)

**Why it matters:** Published secrets stay public forever – including the history.

**To resolve:** Rotate every real credential, remove it from the code and from the history (publish a fresh history), and read secrets from configuration at runtime.

**Settings** (`[checks.secrets]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Private key:** /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/
- **Client secret:** /(?i)\\b(client\[\_-\]?secret)\\b\[\\"'\]?\\s\*\[:=\]\\s\*\[\\"'\]?(\[^\\s\\"'\<>,;\]{8,})/
- **Password assignment:** /(?i)\\b(pass(?:word|wd)?|pwd)\\b\[\\"'\]?\\s\*\[:=\]\\s\*\[\\"'\](\[^\\"'\\s\$\<>{}\]{4,})\[\\"'\]/
- **Password attribute / element:** /(?i)\\b(?:password|passwd)\\s\*=\\s\*\\"(\[^\\"\$\<>{}\\s\]{4,})\\"|\<(?:password|passwd)>(\[^\<\$\\s{\]{4,})\<//
- **Password in configuration file:** /(?im)^\[ \\t\]\*\[\\w.\\-\]\*(?:password|passwd|pwd|secret|credentials?)\[\\w.\\-\]\*\[ \\t\]\*\[=:\]\[ \\t\]\*(\[^\\s\$\<>{}%\\"'\]{4,})\[ \\t\]\*\$/ – only in (no extension), .cfg, .conf, .env, .ini, .prefs, .properties, .toml
- **Password in URL:** /(?i)(?:jdbc:|https?://|ldaps?://)\[^\\s\\"'\<>\]\*?\[:/?\&;\](?:password|pwd)=(\[^\\s\&\\"'\<>;\]{4,})/
- **Credentials in URL:** /(?i)\\b\[a-z\]\[a-z0-9+.-\]\*://\[^\\s/:@\\"'\<>\]{1,64}:(\[^\\s/@\\"'\<>\]{4,})@\[\\w.-\]+/
- **Basic auth header:** /(?i)authorization\\s\*\[:=\]\\s\*\[\\"'\]?basic\\s+(\[A-Za-z0-9+/=\]{12,})/
- **API key / token:** /(?i)\\b(api\[\_-\]?key|access\[\_-\]?token|auth\[\_-\]?token|secret\[\_-\]?key)\\b\[\\"'\]?\\s\*\[:=\]\\s\*\[\\"'\](\[A-Za-z0-9\_\\-./+=\]{16,})\[\\"'\]/
- **Exclusions:** Values that are obviously placeholders (\*\*\*\*, changeme, \${…}, \<…>, 'password', 'test' …) are ignored; a value matched by several rules on the same line counts once. Searched file types: .bat, .cfg, .cmd, .conf, .env, .gradle, .ini, .java, .js, .json, .launch, .md, .prefs, .product, .properties, .ps1, .py, .sh, .toml, .ts, .txt, .xml, .xtend, .yaml, .yml, Dockerfiles and files without extension. Values are masked in this report.

<a id="internal-hosts"></a>

### Internal infrastructure references

Source: [`src/oss_readiness_auditor/checks/internal_hosts.py`](../src/oss_readiness_auditor/checks/internal_hosts.py)

**Why it matters:** Nobody outside the organisation can reach internal systems – and their names do not belong in public.

**To resolve:** Remove internal host names or move them into configuration; keep only documented public endpoints.

**Settings** (`[checks.internal-hosts]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Hosts:** Host names in URLs (http, https, ldap, ftp, jdbc, ssh, git) and git@host: remotes in text files.
- **Lockfiles:** Dependency lockfiles (Cargo.lock, Gemfile.lock, Pipfile.lock, composer.lock, go.sum, npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, poetry.lock, uv.lock, yarn.lock) are skipped: registry and download links of third-party packages.
- **Public allow-list:** Hosts under these domains, localhost and reserved names (.local, .test, .example, .invalid) and reversed-domain identifiers such as http://org.example.model are not reported: w3.org, omg.org, ietf.org, iana.org, unicode.org, ecma-international.org, oasis-open.org, xml.org, xmlsoap.org, json-schema.org, schema.org, purl.org, dublincore.org, openxmlformats.org, xmlns.com, apache.org, mozilla.org, gnu.org, opensource.org, creativecommons.org, spdx.org, reuse.software, pre-commit.com, pre-commit.ci, conventionalcommits.org, semver.org, keepachangelog.com, developercertificate.org, contributor-covenant.org, securityscorecards.dev, sigstore.dev, python.org, nodejs.org, npmjs.org, npmjs.com, pypi.org, pythonhosted.org, maven.org, mvnrepository.com, sonatype.org, gradle.org, github.com, github.io, githubusercontent.com, gitlab.com, bitbucket.org, sourceforge.net, oracle.com, java.com, java.net, sun.com, jcp.org, openjdk.org, openjfx.io, microsoft.com, apple.com, google.com, googleapis.com, android.com, wikipedia.org, docker.com, docker.io, postgresql.org, mysql.com, sqlite.org, junit.org, slf4j.org, qos.ch, fasterxml.com, springframework.org, spring.io, jboss.org, hibernate.org, plantuml.com, graphviz.org, reactjs.org, react.dev, nextjs.org, vercel.com, typescriptlang.org, jquery.com, example.com, example.org, example.net, schemas.microsoft.com, schemas.android.com, eclipse.org, eclipse.dev, eclipsecon.org, polarsys.org, eclipse-ee4j.github.io, jakarta.ee, osgi.org, obeo.fr, xtext.org, railml.org, openrailassociation.org.
- **Internal hint:** Hosts with one of these name parts (optionally followed by digits; the top-level domain is not considered), hosts in the top-level domains corp, home, internal, intra, intranet, lan, local, private, and private IP ranges are marked 'internal-looking': gitlab, gitea, idp, sso, intranet, internal, corp, vpn, ldap, local, dev, uat, staging, preprod, lan, priv, rec, recette.

<a id="domain-data"></a>

### Real-world domain data

Source: [`src/oss_readiness_auditor/checks/domain_data.py`](../src/oss_readiness_auditor/checks/domain_data.py)

**Why it matters:** Data about real infrastructure, customers or operations may only be published with its owner's consent.

**To resolve:** The data owner confirms each file may be published, or it is replaced by synthetic data.

**Settings** (`[checks.domain-data]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **railML:** Files with extension .railml, or XML files whose first 4,000 characters contain a \<railml> element.

<a id="personal-data"></a>

### Personal data

Source: [`src/oss_readiness_auditor/checks/personal_data.py`](../src/oss_readiness_auditor/checks/personal_data.py)

**Why it matters:** Personal data may only be published with consent (GDPR).

**To resolve:** Remove personal data, or obtain consent (e.g. authors who want to be credited).

**Settings** (`[checks.personal-data]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **E-mail addresses:** /\\b\[A-Za-z0-9.\_%+\\-\]{1,64}@\[A-Za-z0-9.\\-\]+\\.\[A-Za-z\]{2,}\\b/ – role and example addresses, git@host remotes and name@file.ext references (ending in a file extension used in the repository) ignored; shown masked.
- **User paths:** Home-folder paths C:\\Users\\\<name>, /home/\<name>, /Users/\<name> – generic names ignored; shown masked.
- **Names in paths:** Path segments of tracked files equal to a user name found above (names that occur in more than 1 % of all paths are ordinary words, not people).

<a id="ownership"></a>

### Ownership and confidentiality notices

Source: [`src/oss_readiness_auditor/checks/ownership.py`](../src/oss_readiness_auditor/checks/ownership.py)

**Why it matters:** An open tool cannot stamp an owner or a confidentiality label on its users' documents.

**To resolve:** Remove ownership and confidentiality labels – especially from templates of generated documents.

**Settings** (`[checks.ownership]`): `enabled` (default `true`), `level` (default `"default"`).

**Rules:**

- **Notices:** Any of /company\\s+confidential/ | /strictly\\s+confidential/ | /\\bconfidential\\s\*\[-:\]\\s\*do\\s+not\\s+(?:distribute|share)/ | /for\\s+internal\\s+distribution\\s+only/ | /propri\[ée\]t\[ée\]\\s+exclusive/ | /ne\\s+peut\\s+\[êe\]tre\\s+(?:reproduit|communiqu|diffus)/ | /\\bconfidentiel(?:le)?\\b/ | /diffusion\\s+restreinte/ | /usage\\s+interne/ | /\\bvertraulich\\b/ | /nur\\s+f\[üu\]r\\s+den\\s+internen/ | /\\bstreng\\s+geheim\\b/ in text files (packs: lang-en, lang-fr, lang-de). Proprietary license headers are reported by the license check, not here.
- **Outside code:** Also, in files that are not code or schema documentation (.c, .cpp, .cs, .go, .groovy, .h, .java, .js, .jsx, .kt, .py, .rs, .scala, .ts, .tsx, .xtend, .exsd): /internal\\s+use\\s+only/ – in code it describes API visibility.

<a id="project-basics"></a>

### Project basics and governance

Source: [`src/oss_readiness_auditor/checks/project_basics.py`](../src/oss_readiness_auditor/checks/project_basics.py)

**Why it matters:** Without a license, maintainers and a way to report issues, nobody can use or contribute safely.

**To resolve:** Add the missing files; LICENSE and README are the minimum.

**Settings** (`[checks.project-basics]`): `enabled` (default `true`), `level` (default `"default"`), `required` (default `["LICENSE", "README"]`): files that must exist (blocker if missing); the others are expected (needs judgement).

**Rules:**

- **Files:** Presence of the files below in the repository root (or .github/ / docs/ for the community files). Required (blocker if missing): CODE\_OF\_CONDUCT, LICENSE, MAINTAINERS, README – setting checks.project-basics.required.
- **LICENSE as REUSE texts:** Without a root LICENSE file, license texts in LICENSES/ (REUSE layout) declare the license: they are reported as detected, the missing root LICENSE file needs judgement, not a blocker. GitHub advises a LICENSE file in the repository root – only from there does it detect and display the repository's license; other platforms and scanners do the same.

<a id="reuse-dco"></a>

### License header on every file (REUSE standard) and commit sign-off (DCO)

Source: [`src/oss_readiness_auditor/checks/reuse_dco.py`](../src/oss_readiness_auditor/checks/reuse_dco.py)

**Why it matters:** REUSE (FSFE standard) means every file states its copyright holder and license in a machine-readable way, so anyone can reuse any file safely. DCO sign-off means every contributor certifies their right to contribute.

**To resolve:** Add a license and copyright header (SPDX) to every file, or declare it in REUSE.toml; put the license texts in LICENSES/; check with the 'reuse lint' tool. Contributors sign off their commits (git commit -s).

**Settings** (`[checks.reuse-dco]`): `enabled` (default `true`), `level` (default `"default"`), `reuse` (default `"judgement"`): files without REUSE license information, `dco` (default `"judgement"`): commits without sign-off.

**Rules:**

- **REUSE coverage:** A file is covered if it has an SPDX-License-Identifier in its first lines, a .license side-car file, or matches a path in REUSE.toml / .reuse/dep5 (simplified glob matching). Below 100 %: judgement (setting checks.reuse-dco.reuse).
- **Not a compliance verdict:** This is a coverage estimate. The REUSE specification has further requirements (valid SPDX expressions, a license text for every license used, ignore markers); confirm compliance with the official tool: 'reuse lint' (https://reuse.software).
- **License texts:** LICENSES/ folder with the texts of all licenses used. LICENSE/COPYING files are exempt, as in the REUSE specification.
- **DCO:** Share of commits whose message contains 'Signed-off-by:' (git history). Below 100 %: judgement (setting checks.reuse-dco.dco).

<a id="openrail"></a>

### OpenRail project criteria

Source: [`src/oss_readiness_auditor/checks/openrail.py`](../src/oss_readiness_auditor/checks/openrail.py)

**Why it matters:** Projects hosted by the OpenRail Association must meet the criteria of their incubation stage; the stage applied for is the target.

**To resolve:** Meet every unmet criterion of the target stage; criteria for a person are answered in the OpenRail questionnaire (https://projects.openrailassociation.org/docs/incubation/process/).

Runs only with the rule pack `openrail`.

**Settings** (`[checks.openrail]`): `enabled` (default `true`), `level` (default `"default"`), `target_stage` (default `1`): stage applied for: 1 Onboarded, 2 Qualified; criteria of higher stages are shown for information.

**Rules:**

- **Source:** OpenRail Project Handbook, incubation process (© OpenRail Association, CC BY 4.0), paraphrased: https://projects.openrailassociation.org/docs/incubation/process/. Not affiliated with or endorsed by the OpenRail Association. Stage 3 (Adopted) is out of scope.
- **Target stage:** Criteria up to the target stage (setting checks.openrail.target\_stage, here 1) count: unmet criteria block, criteria for a person need judgement. Criteria of higher stages are shown for information.
- **Stage 1 · Scope:** Contributes to the challenges of the railway sector.
- **Stage 1 · Description:** README present; the description itself is assessed with the questionnaire.
- **Stage 1 · Maintainers:** MAINTAINERS / CODEOWNERS / GOVERNANCE file, or a 'Maintainers' section in the README.
- **Stage 1 · Code of conduct:** CODE\_OF\_CONDUCT file that adopts the OpenRail Association Code of Conduct (mentions OpenRail).
- **Stage 1 · OSI-approved license:** LICENSE/COPYING text recognised as an OSI-approved license, or OSI-approved SPDX ids in LICENSES/.
- **Stage 1 · Only openly licensed code:** No proprietary clauses (license check) and no restricted third-party licenses (third-party check).
- **Stage 1 · Trademarks:** Intent to transfer the project's trademarks to the Association.
- **Stage 2 · REUSE compliant:** Every file declares its license (coverage estimate as in the REUSE check).
- **Stage 2 · REUSE linter automated:** A CI or pre-commit configuration runs 'reuse lint'.
- **Stage 2 · DCO on all commits:** Every commit in the git history has a 'Signed-off-by:' line.
- **Stage 2 · DCO checked automatically:** .github/dco.yml (DCO app) or a CI job checking sign-offs.
- **Stage 2 · Security policy:** SECURITY file in the root, .github/ or docs/.
- **Stage 2 · Dependencies pinned:** A dependency lockfile; with a Maven/Gradle/Tycho build a person confirms fixed versions.
- **Stage 2 · Automated dependency updates:** Dependabot or Renovate configuration.
- **Stage 2 · OpenSSF Scorecard ≥ 5/10 in README:** The README states an OpenSSF Scorecard; the score itself is checked online.
- **Stage 2 · Changelog:** CHANGELOG/CHANGES/HISTORY/NEWS file, or release notes generated in CI.
- **Stage 2 · Signed release artifacts:** CI signs or attests artifacts (Sigstore/cosign, artifact attestations, GPG, minisign).
- **Stage 2 · SBOM for release artifacts:** CI produces an SBOM (CycloneDX, SPDX, Syft). Recommended, not required. Recommended: needs judgement when unmet.
- **Stage 2 · Open governance:** GOVERNANCE file, or a governance section in the README or CONTRIBUTING file.
- **Stage 2 · Public roadmap:** ROADMAP file or a 'Roadmap' section in the README.
- **Stage 2 · Healthy contributor base:** Assessed by the Technical Committee; commit authors and their e-mail domains are listed.
- **Stage 2 · Used in production:** Assessed with the questionnaire.
- **Stage 2 · Specification reference implementation:** Only for specifications: a public reference implementation.
