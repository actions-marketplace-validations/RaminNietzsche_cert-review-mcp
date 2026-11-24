"""MCP server constants and shared instruction text (schemas stay in mcp_server)."""

SERVER_NAME = "cert-review"
WEBSITE = "https://github.com/RaminNietzsche/cert-review-mcp"

INSTRUCTIONS = """\
SEI CERT C/C++ secure-coding review for local source trees. Every tool only reads local
files and bundled data and runs local analyzers (clang-tidy, clang, cppcheck, and Semgrep,
Infer or CodeQL when installed); nothing is written to the project, uploaded or posted.
Rule lookup: list_rules (structured filters), search_rules (keywords), get_rule (one rule's
full text), get_rule_coverage (what checkers can detect).
Review flow:
1. review_pr for a git change (preferred), or check_diff for a change, or check_files for whole
   files or directories; pass baseline_path
   to hide findings already recorded in a .cert-review-baseline.json.
   explain_finding turns one finding into a rule summary, the closest CERT example and a fix.
2. build_review_packet for rules no checker decides; judge each hunk and write findings
   that cite a candidate rule_id and quote that rule's text verbatim.
3. validate_findings to drop ungrounded findings.
4. format_findings to draft markdown, GitHub or GitLab review payloads, SARIF or GitLab reports.
   format_pr_review merges check_diff + build_review_packet into one PR comment with hints and style nits.
   review_pr and format_pr_review accept github_footer (pull_request_target, mcp, github-action) for
   collapsible attribution; markdown starts with <!-- cert-review --> for comment upsert in CI.
Fork CI: docs/action.md and ci/github/pr-cert-review-mcp.yml — pull_request_target, checkout head SHA,
docker run --entrypoint cert-review review-pr (Hub image entrypoint is cert-review-mcp).
Use absolute paths and profile "ceph" for Ceph trees. A tool status "partial" or non-empty
warnings means some files did not compile or timed out, so a clean result is not proof.
MISRA C:2012, MISRA C++:2023 and AUTOSAR C++14: pass `standard` to the lookup tools or
`standards` (or profile "misra" / "autosar") to check_files and check_diff. Their official
texts are copyrighted and not bundled (IDs, classification, mappings and short summaries only),
so validate_findings needs no quote for them unless the user loaded a licensed rule-texts file.
Never post review comments without the user approving the exact text."""