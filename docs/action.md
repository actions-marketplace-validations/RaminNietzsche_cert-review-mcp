# Use as a GitHub Action or a GitLab include

## GitHub Action

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: RaminNietzsche/cert-review-mcp@v1
  with:
    profile: default
    fail-on: error
    upload-sarif: "true"
```

A complete workflow is in [examples/github-workflow.yml](../examples/github-workflow.yml).

### PR comment on `pull_request_target` (fork mirrors)

For a personal fork (same repo PRs with `pull-requests: write`), you can post the same markdown
as MCP `review_pr` / `format_pr_review` using the published Docker image:

- Trigger: `pull_request_target` (like Ceph `pr-triage.yml`), checkout `pull_request.head.sha`,
  `fetch-depth: 0`.
- Run: `docker run --entrypoint cert-review … review-pr` — the Hub image **entrypoint is
  `cert-review-mcp` (stdio)**; without `--entrypoint cert-review` the CLI never runs.
- Pin `raminnietzsche/cert-review-mcp:latest` (or a version tag after `docker-publish` finishes).
- Upsert: `peter-evans/find-comment` on `<!-- cert-review -->`, then `create-or-update-comment`
  with `comment-id` (`body-includes` alone is not a valid input on v4).
- Optional: `review-pr --github-footer pull_request_target` (v1.4.2+).

Canonical workflow: [examples/github-workflow-pull-request-target-comment.yml](../examples/github-workflow-pull-request-target-comment.yml)
or [ci/github/pr-cert-review-mcp.yml](../ci/github/pr-cert-review-mcp.yml).

How it runs: `action.yml` is a composite action. It builds the repository's `Dockerfile`
(Debian 13, clang/clang-tidy 19.1.7-3+b1, cppcheck 2.17.1-2, Semgrep 1.186.0, the toolchain behind
[accuracy.md](accuracy.md)) and runs `python -m cert_review.action` in it on your workspace.
Building takes a few minutes; set `image` to a prebuilt copy to skip it. Docker must be available
on the runner (it is on `ubuntu-latest`).

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `profile` | `default` | `default`, `ceph`, or a path to a profile YAML in your repository |
| `mode` | `diff` on `pull_request`, else `full` | `diff` reviews only changed lines, `full` reviews `paths` |
| `base-ref` | PR base | Base branch or commit for diff mode (merge-base with `HEAD` is used) |
| `paths` | `.` | Full mode: files or directories, newline or comma separated |
| `include` / `exclude` | none | Globs relative to the repository, applied to findings |
| `compile-commands` | none | `compile_commands.json` or its directory. Strongly recommended |
| `tools` | `clang-tidy,cppcheck` | Add `clangsa` for the standalone analyzer (needs flags that parse) and `semgrep` for the bundled CERT pattern rules (Semgrep 1.186.0 is in the image). `infer` and `codeql` are not in the image; see [analyzers.md](analyzers.md) |
| `min-confidence` | `0.5` | Hide findings below this confidence |
| `fail-on` | `never` | Fail the job at `error`, `warning` or `note` |
| `fail-on-parse-error` | `false` | Fail the job when the analysis was partial: a file had compile errors or an analyzer timed out on it (300 s per file and tool) |
| `baseline` | none | Baseline JSON from `cert-review baseline create`, relative to `working-directory`; recorded findings are not reported, annotated or counted for `fail-on` ([baseline.md](baseline.md)) |
| `sarif-file` | `cert-review.sarif` | SARIF 2.1.0 output path |
| `upload-sarif` | `false` | Upload to code scanning (`github/codeql-action/upload-sarif@v3`); needs `security-events: write` |
| `sarif-category` | `cert-review` | Code scanning category |
| `review-comments` | `false` | Post **one** pull-request review with inline comments |
| `max-comments` | `30` | Most important findings first |
| `github-token` | none | Used only for `review-comments`; needs `pull-requests: write` |
| `working-directory` | `.` | Project directory inside the workspace |
| `image` | none | Prebuilt image instead of building the Dockerfile |

Outputs: `sarif-file`, `findings`, `errors`, `partial` (`true` when some files did not parse or timed out),
`baselined` (findings hidden by `baseline`).

### What it writes

- **SARIF** to `sarif-file`; uploading is the `upload-sarif` toggle, or add the upload step yourself.
- **Job summary** (`$GITHUB_STEP_SUMMARY`): counts, a table of findings with rule links, and a note
  when files had compile errors.
- **Annotations** for up to 50 findings.
- **PR review comments** only when `review-comments: "true"`. They use the same formatter as
  `cert-review diff --format github`: rule ID, severity, why it matters, a compliant example and
  the rule link. A fork pull request has a read-only token, so comments are skipped with a warning.
  Comments are on by explicit choice of the workflow author; leave the input off if a human
  should review the text first and use the SARIF or summary instead.

### Notes

- Without a compile database many files do not parse. The summary says how many were only
  partly analysed. Generate one with `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` before the action.
- `working-directory` other than `.` changes where the SARIF file is written; set `sarif-file`
  accordingly when uploading.
- Pin `@v1` (a moving major tag) or a full commit SHA. Tags are the maintainer's to create.
- Suppress one finding with `// cert-review: ignore RULE-ID reason`.

## GitLab CI include

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/RaminNietzsche/cert-review-mcp/v1/ci/gitlab/cert-review.gitlab-ci.yml'

variables:
  CERT_REVIEW_PROFILE: default
  CERT_REVIEW_FAIL_ON: never
```

The `cert-review` job runs on merge requests, installs the same pinned toolchain and the tool
from `CERT_REVIEW_SOURCE` (default: this repository at `v1`), and publishes
`gl-code-quality-report.json` (MR Code Quality widget) and `gl-sast-report.json` (Security
dashboard) plus a Markdown summary. Variables: `CERT_REVIEW_PROFILE`, `_MODE`, `_PATHS`,
`_COMPILE_COMMANDS`, `_TOOLS`, `_MIN_CONFIDENCE`, `_FAIL_ON`, `_BASELINE` (path of a baseline file
in the repository). It does not post MR comments; to
draft discussion payloads use `cert-review diff --format gitlab` and send them yourself.
Needs `GIT_DEPTH: 0` (set by the job) for diff mode.

## Testing the entrypoint locally

```bash
GITHUB_WORKSPACE=$PWD INPUT_MODE=full INPUT_PATHS=corpus/ERR34-C python3 -m cert_review.action
```
