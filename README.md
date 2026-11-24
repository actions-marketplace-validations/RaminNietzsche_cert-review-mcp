# cert-review-mcp

[![cert-review MCP server – quality and maintenance score on Glama](https://glama.ai/mcp/servers/RaminNietzsche/cert-review-mcp/badges/card.svg)](https://glama.ai/mcp/servers/RaminNietzsche/cert-review-mcp)

SEI CERT C and C++ code review as an MCP server, a CLI and two review skills,
tuned for [Ceph](https://github.com/ceph/ceph), with the same tools for MISRA C:2012,
MISRA C++:2023 and AUTOSAR C++14 ([docs/misra-autosar.md](docs/misra-autosar.md)).

It does three things:

1. **Knows the standards.** `data/rules.json` holds every rule and recommendation of the
   SEI CERT C standard (122 rules, 183 recommendations) and every rule of the SEI CERT C++
   standard (83 rules), with paired noncompliant/compliant examples, the risk row
   (severity, likelihood, detectable, repairable, priority, level), CWE tags and the
   automated-detection tables. It is built reproducibly from a pinned upstream commit and
   checked against the standards' own index pages.
2. **Runs real analyzers and maps them to rule IDs.** clang-tidy (`cert-*` and mapped checks),
   the Clang Static Analyzer, cppcheck and 42 bundled Semgrep rules for INT, EXP, MEM, CON and
   other CERT rules; optionally Infer and the CodeQL CERT query packs
   ([docs/analyzers.md](docs/analyzers.md)). Findings are normalised to one schema,
   de-duplicated, filtered by a profile, and optionally limited to changed lines.
3. **Prepares the rest for a manual review layer without letting it make things up.** For rules
   no checker covers, `build_review_packet` selects code hunks and the few rule texts worth reading;
   `validate_findings` rejects any finding that does not cite an existing rule ID and quote
   that rule's text.
4. **Speaks MISRA and AUTOSAR too.** A `standard` filter on every rule tool and a
   `standards` selection for the checks (default: CERT only). Findings map to MISRA C:2012
   (cppcheck MISRA addon), MISRA C++:2023 and AUTOSAR C++14 IDs. Their copyrighted texts are
   not bundled; you can load your licensed copy. See [MISRA and AUTOSAR](#misra-and-autosar).

Comments are only drafted and formatted. **Nothing is ever posted** to GitHub or GitLab by this
project.

> Not an official CERT or CMU product. See [NOTICE](NOTICE) for attribution (CC BY 4.0 text,
> MIT examples) and the pinned source commit.

## Architecture

![Architecture: data built by tools/, the engine in src/cert_review, and the MCP and CLI front ends](https://raw.githubusercontent.com/RaminNietzsche/cert-review-mcp/main/docs/images/architecture.png)

The diagram source is in [docs/architecture.md](docs/architecture.md).

## Coverage

Each rule is `deterministic` (a rule-specific checker exists: a clang-tidy `cert-*` check or a
CodeQL CERT query), `partial` (only general checkers or the bundled Semgrep pattern rules map)
or `llm-only` (no checker). The *reference toolchain* is what the Docker images run:
clang-tidy/clang 19.1.7, cppcheck 2.17.1 and Semgrep 1.186.0 with the bundled rules. The
*extended toolchain* adds Infer 1.3.0 and CodeQL 2.27 with the CERT packs 2.63.0, which are
optional and not in the images.

| Set | Total | All mappings: det / partial / llm-only | Reference toolchain | Extended toolchain |
|---|---|---|---|---|
| C rules | 122 | 100 / 12 / 10 | 16 / 51 / 55 | 100 / 8 / 14 |
| C recommendations | 183 | 4 / 6 / 173 | 4 / 4 / 175 | 4 / 5 / 174 |
| C++ rules | 83 | 82 / 0 / 1 | 18 / 31 / 34 | 82 / 0 / 1 |

Before the Semgrep rules, the reference toolchain covered C rules 16 / 34 / 72 and C++ rules
18 / 29 / 36. A mapped checker is not a detection guarantee; the measured numbers follow.

MISRA C:2012 221 guidelines (131 / 28 / 62), MISRA C++:2023 178 (4 / 31 / 143), AUTOSAR
C++14 397 (5 / 51 / 341); details and measurements in [docs/misra-autosar.md](docs/misra-autosar.md).

Measured precision and recall on the CERT examples: [docs/accuracy.md](docs/accuracy.md).
Rule counts versus the official index pages: [docs/rule-counts.md](docs/rule-counts.md).
Results on a real Ceph subtree: [docs/ceph-trial.md](docs/ceph-trial.md).

Recall on real security fixes (Ceph CVEs and memory-safety fixes, curl, libtiff and others):
[docs/benchmark-real.md](docs/benchmark-real.md).

## Install

```bash
git clone <this repository> cert-review-mcp && cd cert-review-mcp
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
sudo apt-get install clang clang-tidy cppcheck       # static layer (optional but recommended)
pip install semgrep==1.186.0                        # optional: the bundled CERT pattern rules
pytest                                              # 190 tests
```

The package reads `data/` and `profiles/` from the checkout (set `CERT_REVIEW_HOME` to point
elsewhere). Python 3.11+; works with the official `mcp` SDK 1.x (`FastMCP`, 1.15 or later) and 2.x (`MCPServer`).

### Cursor

`.cursor/mcp.json` in your project (or `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "cert-review": {
      "command": "/path/to/cert-review-mcp/.venv/bin/cert-review-mcp",
      "env": { "CERT_REVIEW_HOME": "/path/to/cert-review-mcp" }
    }
  }
}
```

Then ask: "Use the cert-review `ceph_review` prompt on my current diff." Copy `skills/` into your
skills folder to make the review procedure available.

### Docker

`Dockerfile.mcp` builds the MCP server with the analyzers included (no local clang or
cppcheck needed). Mount your project at the same absolute path it has on the host:

```bash
docker build -f Dockerfile.mcp -t cert-review-mcp .
```

```json
{
  "mcpServers": {
    "cert-review": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "/home/me/proj:/home/me/proj:ro", "cert-review-mcp"]
    }
  }
}
```

The same `mcpServers` block works in Claude Desktop and Cursor. Release tags also publish
multi-arch images (amd64, arm64) to Docker Hub as
[`raminnietzsche/cert-review-mcp`](https://hub.docker.com/r/raminnietzsche/cert-review-mcp);
use `raminnietzsche/cert-review-mcp:latest` instead of `cert-review-mcp` to skip the build.
Details, the CLI from the image, and a `tools/list` check: [docs/docker.md](docs/docker.md).

### MCP Registry

The server is listed in the official [MCP Registry](https://registry.modelcontextprotocol.io)
as `io.github.RaminNietzsche/cert-review-mcp` ([server.json](server.json)), so clients that read
the registry can install the Docker image from there.

### Claude Code

```bash
claude mcp add cert-review -- /path/to/cert-review-mcp/.venv/bin/cert-review-mcp
mkdir -p ~/.claude/skills && cp -r skills/cert-review skills/ceph-cert-review ~/.claude/skills/
```

## Use as a GitHub Action

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: RaminNietzsche/cert-review-mcp@v1
  with:
    profile: default            # or ceph, misra, autosar
    fail-on: error
    upload-sarif: "true"        # SARIF to code scanning
```

Diff mode on pull requests, SARIF, a job summary, and optional inline review comments
(`review-comments: "true"`, off by default). A GitLab include template publishes Code Quality
and SAST reports. Inputs, outputs and examples: [docs/action.md](docs/action.md),
[examples/github-workflow.yml](examples/github-workflow.yml).

Fork PR comment (MCP-style markdown via `review-pr` + Docker Hub): 
[examples/github-workflow-pull-request-target-comment.yml](examples/github-workflow-pull-request-target-comment.yml).

## MCP tools

Every tool is read-only: it reads local files and bundled data and runs local analyzers.
Nothing is written, uploaded or posted. All tools declare MCP annotations, a title and,
except `format_findings`, an output schema.

For `check_diff` and `build_review_packet`, analysis runs in a **private temporary workspace**
(the checkout is not modified). With git refs, file bodies come from `git show head:path`; with
pasted `diff_text` they are reconstructed from the patch. Pass `repo` as the logical root for
paths in the diff; findings and SARIF use repository paths, not the temp directory.
Optional `diff_context` keeps findings within N lines of a change (lower confidence).

| Tool | Purpose |
|---|---|
| `list_rules(standard, lang, category, kind, classification, level, detectable, coverage, limit)` | Filter the rule database; summaries with coverage tier |
| `search_rules(query, standard, limit, lang)` | Rank rules by keyword relevance (API names, concepts, IDs) |
| `get_rule(rule_id, profile, include_examples)` | One rule or guideline: text or summary, examples, risk row or classification, CWE, checkers, cross-references, profile notes |
| `get_rule_coverage(standard, lang, kind, include_ids)` | Rule counts per tier: deterministic / partial / llm-only |
| `check_files(path, profile, standards, compdb, root, lang, tools, ...)` | Analyzer findings for a file or a directory tree |
| `check_diff(repo, base, head \| diff_text, profile, standards, compdb, diff_context, ...)` | Analyzer findings on changed lines (optional nearby context) |
| `explain_finding(finding, profile, context_lines)` | One finding: rule summary, why it matches, closest noncompliant/compliant example pair, fix steps |
| `build_review_packet(path \| repo + base \| diff_text, ...)` | Code hunks plus candidate rule texts for manual review |
| `validate_findings(findings, packet, profile)` | Accept only grounded findings (rule ID + verbatim quote; MISRA/AUTOSAR quotes only when a licensed text is loaded) |
| `format_findings(findings, style, root, warnings)` | `markdown`, `github`, `gitlab`, `sarif`, `codequality` or `gitlab-sast`; formatting only |
| `format_pr_review(check_result, packet, title, scope, …)` | One markdown PR comment: static summary, heuristic hints, style nits |
| `review_pr(repo, base, head, profile, …)` | **Preferred for PRs:** runs `check_diff` + `build_review_packet` + `format_pr_review` |

`check_files` and `check_diff` take an optional `baseline_path`: findings recorded in a
baseline file are hidden and counted (new, baselined, fixed). See [docs/baseline.md](docs/baseline.md).

MCP tool and parameter names changed after the `v1` release; see [CHANGELOG.md](CHANGELOG.md).

`standard` accepts `cert` (default), `cert-c`, `cert-cpp`, `misra`, `misra-c-2012`,
`misra-cpp-2023`, `autosar`, `autosar-cpp14` or `all`.

Resources: `rule://EXP34-C`, `profile://ceph`. Prompts: `cert_review`, `ceph_review`.

## CLI

```bash
cert-review version
cert-review check src/common/Throttle.cc --profile ceph --compdb build --format markdown
cert-review diff --repo ~/ceph --base origin/main --profile ceph --diff-context 3 --format sarif -o out.sarif
cert-review diff --diff-file change.patch --format github > review.json   # payload only
cert-review explain EXP34-C
cert-review explain-finding ERR34-C --file src/parse.c --line 42     # closest example + fix
cert-review baseline create src --compdb build                      # record existing findings
cert-review check src --compdb build --baseline .cert-review-baseline.json --fail-on warning
cert-review coverage --lang cpp
cert-review rules --lang cpp --coverage llm-only
cert-review packet --repo ~/ceph --base origin/main --profile ceph -o packet.json
cert-review validate findings.json --packet packet.json
cert-review check src --profile misra                       # MISRA C:2012 + MISRA C++:2023
cert-review check src --standards autosar-cpp14,cert        # AUTOSAR and CERT IDs together
cert-review rules --standard misra-c-2012 --classification mandatory
cert-review explain MISRA-C-2012-17.2
```

`--fail-on error|warning|note` sets the exit code for CI; with `--baseline` only new findings count. Silence one rule on a line with
`// cert-review: ignore EXP34-C reason`.

## Profiles

`profiles/default.yaml` is plain CERT. `profiles/ceph.yaml` encodes Ceph: C++23/C11,
priority and severity per rule, suppressions with reasons (ceph_assert, dout, crimson,
tests, vendored trees), and idioms (bufferlist, `ceph::mutex`, `RefCountedObject`, errno
returns, asio/seastar callbacks) that tell the reviewer how each project construct
changes a rule. Evidence for each idiom is cited inside the file.
`profiles/misra.yaml` and `profiles/autosar.yaml` select MISRA C:2012 + MISRA C++:2023 and
AUTOSAR C++14 (`standards:`), with severity taken from the guideline classification.

## MISRA and AUTOSAR

| Standard | Guidelines | Mandatory / required / advisory | Mapped to a checker |
|---|---|---|---|
| MISRA C:2012 (Amendments 1-4, the MISRA C:2023 set) | 221 | 23 / 150 / 48 | 159 (131 by the cppcheck MISRA addon) |
| MISRA C++:2023 | 178 | 5 / 123 / 50 | 35 |
| AUTOSAR C++14 (AP 19-03) | 397 | - / 362 / 35 | 56 |

The MISRA and AUTOSAR documents are copyrighted, so **none of their guideline text is
included**: only IDs, classification, AUTOSAR enforcement and target, checker mappings,
public SEI CERT cross-references and one-line summaries written for this project
(labelled as paraphrases). Point `CERT_REVIEW_MISRA_C_TEXTS`, `CERT_REVIEW_MISRA_CPP_TEXTS`,
`CERT_REVIEW_AUTOSAR_TEXTS` or a profile's `rule_texts:` at your licensed copy to see the
official headlines and to have `validate_findings` check quotes against them. Without it,
MISRA/AUTOSAR findings are accepted on a valid rule ID (`grounding: "rule-id-only"`).
Mapping sources, measured results and file formats: [docs/misra-autosar.md](docs/misra-autosar.md).

## Rebuilding the data

```bash
git clone https://github.com/cmu-sei/secure-coding-standards cert-src
python3 tools/build_rules.py --src cert-src            # fails if counts differ from the index pages
python3 tools/build_checker_map.py --codechecker <codechecker clone> --llvm <llvm-project clone>
python3 tools/build_corpus.py && python3 tools/eval_accuracy.py
python3 tools/build_guidelines.py --cppcheck <cppcheck 2.17.1 clone> --autosar autosar.txt  # MISRA/AUTOSAR
cert-review compdb --repo ~/ceph --tracked                    # cached synthetic compile db
python3 tools/ceph_compdb.py --ceph ~/ceph --tracked          # same (wrapper CLI)
```

## Limitations

- Static coverage is thin by nature: most CERT rules are not decidable by tools; the
  `llm-only` and `partial` rules depend on the review layer and on a human.
- Tools need compilable code. Without `compile_commands.json` many files do not parse and
  checks are skipped. The engine reports this instead of "no findings": the tool status
  becomes `partial`, the markdown, SARIF (`executionSuccessful: false` plus a
  `toolExecutionNotifications` warning), GitHub review, Action summary and CLI output carry a
  warning, and `--fail-on-parse-error` (alias `--fail-on-partial`; Action input
  `fail-on-parse-error`) turns it into a failing exit code. A file on which an analyzer hits
  its 300 s timeout is treated the same way. See [docs/execution.md](docs/execution.md) for
  Ceph builds, diff mode, and `tools/ceph_compdb.py`.
- **Ceph needs Linux.** Its sources include Linux-only headers (`linux/version.h`, ...) and
  Linux-only Boost.Asio features, so e.g. `src/rgw/radosgw-admin/radosgw-admin.cc` cannot be
  parsed on macOS even with the SDK sysroot and Homebrew Boost. Analyse Ceph on Linux, with the
  Docker image, or with the GitHub Action. `tools/ceph_compdb.py` adds `-isysroot` on macOS, which
  is enough for some directories (`src/common`) but not for all of them.
- Mappings come from CodeChecker labels and clang-tidy aliases plus a small curated overlay;
  general analyzers can map to several rules, so the engine keeps the best few per line.
- Most MISRA C++ and AUTOSAR guidelines have no open-source checker; MISRA C coverage
  depends on cppcheck's MISRA addon (needs `python3`).
- Ceph's profile is based on reading the code and on a limited trial, not on a full build.

## License

Code: Apache-2.0 ([LICENSE](LICENSE)). Bundled CERT content: CC BY 4.0 (text) and MIT
(examples); see [NOTICE](NOTICE). MISRA and AUTOSAR: facts and original summaries only, no
guideline text; see [NOTICE](NOTICE) and [docs/misra-autosar.md](docs/misra-autosar.md).
