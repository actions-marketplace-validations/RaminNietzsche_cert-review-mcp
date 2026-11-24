# Changelog

## Unreleased

## 1.4.4 (2026-11-23)

### Added

- Tests: `tests/test_github_footer.py` (API, CLI, workflow YAML, server.json),
  MCP schema checks for `github_footer`, `tiny_git_repo` fixture in conftest.

### Fixed

- `pyproject.toml` version aligned with `__version__` (1.4.3).

## 1.4.3 (2026-11-23)

### Added

- MCP **`review_pr`**: `github_footer` parameter (parity with CLI / `format_pr_review`).
- Docs: `pull_request_target` fork workflow (`docs/action.md`, `docs/docker.md` entrypoint note).
- Canonical workflow copy under `ci/github/pr-cert-review-mcp.yml`.

### Fixed

- Example workflow aligned with production fork CI (`--entrypoint cert-review`, `find-comment` upsert).

## 1.4.2 (2026-11-23)

### Added

- `format_pr_review` / `review-pr` optional **`github_footer`** (`pull_request_target`, `mcp`,
  `github-action`): collapsible cert-review-mcp attribution for automated PR comments.
- Example workflow `examples/github-workflow-pull-request-target-comment.yml` (same trigger style
  as Ceph `pr-triage.yml`: `pull_request_target` + upsert via `<!-- cert-review -->`).

## 1.4.1 (2026-11-22)

### Fixed

- CLI `review-pr`: remove duplicate `--profile` (and related flags) that broke argparse and
  failed self-test on Python 3.12.

## 1.4.0 (2026-11-22)

### Added

- MCP/CLI **`review_pr`**: one call runs `check_diff`, `build_review_packet`, and `format_pr_review`.
- `cert-review review-pr` with `--report` for full JSON.

### Improved

- `format_pr_review`: warning lines shorten temp paths to `` `src/...` ``; hunk locations use `src/` paths.
- MCP prompts and docs list `review_pr` as the preferred PR workflow.

## 1.3.3 (2026-11-22)

### Added

- `format_pr_review` (MCP + `cert-review format-pr`): single markdown PR comment with static tool
  summary, `build_review_packet` heuristic table, Ceph idiom hints, CodingStyle nits, and
  auto-suggested functional bullets when the packet mentions sync/RGW paths.

## 1.3.2 (2026-11-22)

### Added

- `cert-review compdb --repo <ceph> --tracked`: cached synthetic `compile_commands.json` under
  `<repo>/.cert-review/compdb-cache/<tree-id>/` (refreshes when `HEAD` or dirty worktree changes).
- `cert_review.ceph_compdb`: shared library; `git show` materializes sources missing on disk;
  headers (`.h`) in synthetic entries; RGW admin include paths and `WITH_RADOSGW_*` defs.
- Ceph profile: `synthetic_compdb_cache` uses the cache when `head` matches the checkout;
  otherwise a diff-scoped synthetic DB for the analysed ref.

### Changed

- `find_compdb` also checks `<repo>/.cert-review/compdb-cache/current`.

## 1.3.1 (2026-11-22)

### Added

- Ceph profile: when `repo` has no `compile_commands.json`, `check_diff` /
  `build_review_packet` auto-build a temporary synthetic compdb (`diff_review.synthetic_compdb`).
- `cert_review.ceph_compdb` module (CLI `tools/ceph_compdb.py` wraps it).

### Added

- [docs/execution.md](docs/execution.md): prerequisites for trustworthy runs (Ceph, compdb, diff).
- `tools/ceph_compdb.py --git-diff` and extra RGW include paths.

### Fixed

- Diff mode: `compile_commands.json` entries match analysed files by `src/...` path, so a PR
  worktree still gets real flags when `compdb` points at the Ceph checkout. `compdb` is also
  discovered under `repo/build`, not only under the temp workspace.
- cppcheck uses `--project` only for files present in the database.
- Ceph profile: default `diff_context: 3`; partial runs link to [docs/execution.md](docs/execution.md).

## 1.3.0 (2026-11-22)

### Added

- `cert-review version` prints the package version and installed source path.
- `diff_context` on diff mode (CLI `--diff-context`, MCP `check_diff`): findings within N lines of
  a change are kept with confidence scaled by 0.85.
- `data/confidence_calibration.json` and `tools/calibrate_confidence.py` for checker confidence on
  the dev corpus half (partial mappings only).
- Semgrep rules `int04-c-ntohl-fed-allocation` and `exp34-c-map-find-dereference` in
  `data/semgrep/ceph.yml` (42 bundled Semgrep rules total).
- CI matrix over clang 18/19/20 and a job that runs `pytest` inside the MCP Docker image.

### Fixed

- Diff mode uses a private temporary workspace only; content comes from `git show head:path` when
  possible; the tree is removed after the run and the checkout is never modified.
- `git diff` for review uses merge-base syntax (`base...head`).
- Finding paths in diff results are mapped back to the repository for SARIF, the GitHub Action and
  path filters (no `cert-review-work-*` URIs).
- `build_review_packet` reuses one workspace for static findings and hunks.
- `engine.check` drops findings outside the requested files except project headers allowed by
  `header_filter`.
- clang-tidy notes and partial status when a file is missing from `compile_commands.json`.
- cppcheck uses `--project=compile_commands.json` when available and treats syntax/preprocessor
  errors as partial analysis.

### Changed

- Taint integration tests skip when the installed clang does not report `fgets` → `printf` taint.
- MCP `check_diff` / `build_review_packet` descriptions reflect the read-only diff workspace.

## 1.2.0 (2026-11-21)

### Added

- MISRA C:2012 (Amendments 1-4, 221 guidelines), MISRA C++:2023 (178) and AUTOSAR C++14
  (397) next to SEI CERT, in `data/guidelines.json` (built by `tools/build_guidelines.py`
  from cppcheck 2.17.1's guideline lists and the public AUTOSAR document, plus
  `data/guideline_overlay.yaml`). No MISRA or AUTOSAR guideline text is bundled: only IDs,
  classification, AUTOSAR enforcement/target, checker mappings, SEI CERT cross-references and
  one-line summaries written for this project. See [docs/misra-autosar.md](docs/misra-autosar.md)
  and [NOTICE](NOTICE).
- `standard` parameter on `list_rules`, `search_rules` and `get_rule_coverage` (`cert` default,
  `cert-c`, `cert-cpp`, `misra`, `misra-c-2012`, `misra-cpp-2023`, `autosar`, `autosar-cpp14`,
  `all`); `classification` filter and `directive` kind on `list_rules`; `get_rule` accepts
  MISRA/AUTOSAR IDs and short forms and lists CERT cross-references both ways.
- `standards` parameter on `check_files` and `check_diff` (CLI `--standards`). With
  `misra-c-2012`, cppcheck runs its MISRA addon on C files; cppcheck, clang-tidy and Clang
  Static Analyzer findings map to MISRA/AUTOSAR IDs. Findings carry a `standard` field.
- Profiles: `standards:`, `severity_from_classification:` and `rule_texts:`; new
  `profiles/misra.yaml` and `profiles/autosar.yaml`.
- Licensed rule texts: `CERT_REVIEW_MISRA_C_TEXTS`, `CERT_REVIEW_MISRA_CPP_TEXTS`,
  `CERT_REVIEW_AUTOSAR_TEXTS` or the profile's `rule_texts` load a local copy (cppcheck addon
  format or one guideline per line), used by `get_rule`, finding messages and
  `validate_findings`.
- `tools/measure_guidelines.py` for the coverage table.
- `explain_finding` MCP tool and `cert-review explain-finding` command: for one finding, the rule
  summary, why the finding matches (checker mapping, APIs, shared identifiers), the rule's
  noncompliant/compliant example pair closest to the flagged code, a diff between the two and
  concrete fix steps. Deterministic and offline. The server now has 10 tools.
- Baselines: `cert-review baseline create|update` writes `.cert-review-baseline.json` with
  line-number-free fingerprints (rule, file, hash of the normalized line, hash of its
  neighbours). `--baseline FILE` on `check` and `diff`, `baseline_path` on the `check_files` and
  `check_diff` tools, the Action's `baseline` input (and `baselined` output) and the GitLab
  template's `CERT_REVIEW_BASELINE` report only new findings and count baselined and fixed
  ones. See `docs/baseline.md`.
- Optional analyzers, normalised into the same finding schema and checker map:
  - **Semgrep** with 40 CERT rules shipped in `data/semgrep/` for INT30/33/34/36-C,
    EXP34/44/45/46-C, EXP52-CPP, MEM30/34/35-C, MEM50/51-CPP, CON31/34/36/39/40/41-C,
    CON50/54-CPP, POS34/48/50/53-C, ENV30-C, FIO30/34/37-C and STR30-C. Included in both
    Docker images (amd64 and arm64).
  - **Infer** (Pulse, InferBO, liveness, RacerD, starvation, SIOF); 28 issue types mapped in
    `data/checker_overlay.yaml`. Not in the images (about 1.2 GB, no Linux arm64 release).
  - **CodeQL** with the `codeql/cert-c-coding-standards` and `codeql/cert-cpp-coding-standards`
    packs (232 queries mapped). Opt-in; not in the images and not run in CI.
- `tools` (CLI `--tools`, MCP `tools`, Action `tools`) accepts `semgrep`, `infer`, `codeql` and
  `auto`. The default is now `auto`: the core tools plus Semgrep and Infer when they are on
  `PATH`. A requested analyzer that is not installed adds a `warnings` entry.
- `tier_extended` per rule and `extended_toolchain` in `get_rule_coverage`: coverage with Infer
  and CodeQL installed. `tier_runnable` now counts the reference toolchain of the images,
  which includes Semgrep.
- `docs/analyzers.md`: install notes, tiers, what each analyzer covers, a Ceph sanity check of
  the Semgrep rules.
- `tools/eval_accuracy.py` measures each toolset (baseline, + Semgrep, + Infer, + CodeQL) and
  reports corpus-wide recall; CodeQL is evaluated with one database per example.
- Real-code benchmark: `benchmark/cases.yaml` (upstream security fixes in Ceph, curl, libtiff,
  expat, libarchive, c-ares and OpenSSL), `tools/run_real_benchmark.py` and
  [docs/benchmark-real.md](docs/benchmark-real.md).

### Changed

- `validate_findings`: for MISRA/AUTOSAR without a licensed text file, `quote` is optional and
  accepted findings are marked `grounding: "rule-id-only"`; SEI CERT still requires a verbatim
  quote. All accepted findings now carry `grounding`.
- Formatter headings name the selected standards; SARIF tags use `external/cert/`, `external/misra/` or `external/autosar/` plus the ID.
- Docker images grow by about 330 MB (MCP image 787 MB to 1.12 GB, Action image 957 MB to
  1.29 GB, uncompressed, amd64) for Semgrep.

### Fixed

- cppcheck output lines whose ID contains `-` or `.` were dropped by the parser.

### Accuracy (CERT examples, docs/accuracy.md)

- Corpus-wide recall (detected noncompliant examples / 708): 15% with clang-tidy, clangsa and
  cppcheck; 20% with Semgrep added (the image toolchain; in-sample, the rules were written
  against these examples); 20% with Infer; 28% with CodeQL. False positives on the 840
  compliant examples: 5, 5, 5 and 28.
- On the 103 rules the baseline scores: precision/recall 95%/42% before, 96%/46% with Semgrep,
  88%/54% with all analyzers.

The default standard selection (CERT only) is unchanged for existing calls, profiles and CI jobs.

## 1.1.2 (2026-11-21)

### Added

- `server.json` for the official MCP Registry: `io.github.RaminNietzsche/cert-review-mcp`,
  OCI package `docker.io/raminnietzsche/cert-review-mcp`.
- `Dockerfile.mcp` sets the `io.modelcontextprotocol.server.name` label that the registry uses
  to verify image ownership.
- `mcp-registry` workflow: after a release image is pushed, publishes `server.json` to the
  registry with GitHub OIDC (no stored token).

No changes to the tools, the CLI or the GitHub Action.

## 1.1.1 (2026-11-21)

### Fixed


- `check_diff` and `build_review_packet` with `diff_text` now materialize missing files from the
  patch instead of returning empty results when the MCP host cannot see the local checkout (e.g.
  remote/Glama servers with a placeholder `repo` path).
- MCP `check_diff` no longer requires `repo` to exist on disk when `diff_text` is provided.

## 1.1.0 (2026-11-21)

### Breaking changes for MCP clients

The CLI (`cert-review ...`), the GitHub Action and the GitLab CI templates are unchanged.
Only clients that call the MCP tools by name need updating.

| Before | After |
|---|---|
| `explain_rule(id, ...)` | `get_rule(rule_id, ...)` |
| `rule_coverage` | `get_rule_coverage` |
| `check_file` | `check_files` |
| `review_packet` | `build_review_packet` |
| `format_review` | `format_findings` |
| `list_rules`, `search_rules`, `check_diff`, `validate_findings` | unchanged names |

- `validate_findings` takes `findings` (JSON array) and `packet` (JSON object) instead of the
  `findings_json` and `packet_json` strings. `format_findings` takes `findings` as an array.
- `check_diff` requires `repo`; git refs and `diff_text` paths are resolved against it.
- Enum filters use `"any"` for "no filter" instead of `null` (`lang`, `category`, `kind`,
  `level`, `coverage`). Unknown values are rejected instead of returning an empty list.
- `list_rules` returns 50 summaries by default (was 200); raise `limit` up to 400.
- Unknown rule IDs, unknown profiles and missing paths are tool errors instead of empty or
  `{"error": ...}` results.
- Requires `mcp>=1.15`.

### Added

- Every tool has a title, MCP annotations (read-only, non-destructive, idempotent, closed
  world), a description of every parameter and, except `format_findings`, an output schema.
- `get_rule(include_examples=false)` returns text and risk without code examples.
- `build_review_packet(compdb=...)`, so the static pass inside it can use a compilation database.
- `format_findings(warnings=...)` carries partial-analysis warnings into markdown, GitHub and
  SARIF output; `codequality` and `gitlab-sast` styles are listed.
- `Dockerfile.mcp` and [docs/docker.md](docs/docker.md): an image that runs the MCP server over stdio (and the CLI with
  `--entrypoint cert-review`), for local use and the Glama registry build.
- `glama.json`.
- `.github/workflows/docker-publish.yml`: on a `v*.*.*` tag, builds `Dockerfile.mcp` for
  linux/amd64 and linux/arm64, checks that it answers `tools/list`, and pushes
  `<DOCKERHUB_USERNAME>/cert-review-mcp:<version>` and `:latest`.

### Fixed


- An analyzer timeout (300 s per file and tool) makes the tool status `partial` and adds a
  warning, like a compile error; it used to appear only under `notes`. `--fail-on-parse-error`
  (new alias `--fail-on-partial`) and the Action input `fail-on-parse-error` fail on it.
- Error messages reach mcp 2.x clients (they were replaced by "Error executing tool ...").
- `pip install` from a wheel or git URL ships `data/` and `profiles/`; previously every tool
  failed unless `CERT_REVIEW_HOME` was set.
