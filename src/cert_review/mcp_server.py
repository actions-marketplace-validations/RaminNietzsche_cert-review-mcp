"""MCP server (stdio) exposing the SEI CERT, MISRA and AUTOSAR rule databases and review engine.

Nothing here writes files, uses the network, or posts to GitHub or GitLab:
review comments are only formatted.
"""
from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from mcp.types import ToolAnnotations

from . import api
from . import profiles as P
from . import rules as R
from .mcp_schemas import INSTRUCTIONS, SERVER_NAME, WEBSITE

try:                                   # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:                    # mcp 1.x (>= 1.10 for title/annotations/structured output)
    from mcp.server.fastmcp import FastMCP as _Server
    from mcp.server.fastmcp.exceptions import ToolError

# ---------------------------------------------------------------- shared types
Profile = Annotated[str, Field(
    description="Review profile: 'default' (plain SEI CERT), 'ceph' (Ceph severities, "
                "suppressions and idioms), 'misra' (MISRA C:2012 + MISRA C++:2023), 'autosar' "
                "(AUTOSAR C++14) or an absolute path to a profile .yaml file.",
    examples=["default", "ceph", "misra"])]
_CI = lambda w: "".join(f"[{c.upper()}{c.lower()}]" if c.isalpha() else c for c in w)  # noqa: E731
RULE_ID_PATTERN = (
    r"^(?:[A-Za-z]{3}\d{2}-(?:[Cc]|[Cc][Pp][Pp])"
    rf"|{_CI('MISRA-C-2012-')}(?:{_CI('DIR-')})?\d+\.\d+"
    rf"|{_CI('MISRA-CPP-2023-')}(?:{_CI('DIR-')})?\d+\.\d+\.\d+"
    rf"|{_CI('AUTOSAR-')}[AaMm]\d+-\d+-\d+)$")
RuleId = Annotated[str, Field(
    description="Rule ID, case-insensitive. SEI CERT: category, two digits, -C or -CPP "
                "(EXP34-C). MISRA C:2012: MISRA-C-2012-<n.n> or MISRA-C-2012-DIR-<n.n>. MISRA "
                "C++:2023: MISRA-CPP-2023-<n.n.n> (DIR- for directives). AUTOSAR C++14: "
                "AUTOSAR-<A|M>n-n-n.",
    pattern=RULE_ID_PATTERN,
    examples=["EXP34-C", "MEM50-CPP", "MISRA-C-2012-10.4", "MISRA-CPP-2023-8.2.2", "AUTOSAR-A5-2-2"])]
StandardName = Literal["cert-c", "cert-cpp", "misra-c-2012", "misra-cpp-2023", "autosar-cpp14"]
StandardFilter = Literal["cert", "cert-c", "cert-cpp", "misra", "misra-c-2012", "misra-cpp-2023",
                         "autosar", "autosar-cpp14", "all"]
STANDARD_DOC = ("Rule set: cert = SEI CERT C and C++ (default; the only standard with full rule "
                "text); misra = MISRA C:2012 (with Amendments 1-4, i.e. the MISRA C:2023 set) and "
                "MISRA C++:2023; autosar = AUTOSAR C++14; or one standard by name; all = every "
                "standard.")
Classification = Literal["any", "mandatory", "required", "advisory", "document"]
Tool = Literal["clang-tidy", "clangsa", "cppcheck", "semgrep", "infer", "codeql"]
ALL_TOOLS: list[str] = ["clang-tidy", "clangsa", "cppcheck", "semgrep", "infer", "codeql"]
Tools = Annotated[list[Tool] | None, Field(
    description="Analyzers to run; omit for the default set: clang-tidy, clangsa and cppcheck "
                "plus semgrep and infer when installed. clang-tidy = cert-*/bugprone checks plus "
                "Clang Static Analyzer checks; clangsa = standalone `clang --analyze` (adds alpha "
                "checkers); cppcheck = cppcheck; semgrep = the bundled CERT pattern rules; infer "
                "= Infer (null, leak, use-after-free, overflow, race); codeql = the CodeQL CERT "
                "query packs, opt-in because each run builds a database (tens of seconds or "
                "more). A requested analyzer that is not installed is skipped and listed in "
                "`warnings`.",
    min_length=1, json_schema_extra={"uniqueItems": True},
    examples=[["clang-tidy", "cppcheck", "semgrep"], ["codeql"]])]
MinConfidence = Annotated[float, Field(
    ge=0.0, le=1.0,
    description="Drop findings below this confidence. Rule-specific checkers score 0.9, "
                "general checkers 0.3-0.65, +0.1 when two tools agree. 0.5 keeps most real hits.")]
IncludeSuppressed = Annotated[bool, Field(
    description="Also return findings hidden by the profile or by `// cert-review: ignore "
                "<RULE>` comments, each with its suppression reason (for audits).")]
Compdb = Annotated[str | None, Field(
    description="Absolute path of the directory that contains compile_commands.json. Strongly "
                "recommended: without it files are compiled with guessed flags and often fail "
                "to parse. Omitted: auto-detected in root, root/build or root/build-clang.",
    examples=["/home/me/ceph/build"])]
BaselinePath = Annotated[str | None, Field(
    description="Absolute path of a baseline JSON written by `cert-review baseline create`. Findings "
                "recorded there are left out and counted in `baseline`; file paths in it are relative "
                "to its directory. Matching uses rule, file and hashes of the code line and its "
                "neighbours, so line shifts do not resurface old findings. Omit to report everything.",
    examples=["/home/me/ceph/.cert-review-baseline.json"])]
LANGS = Literal["any", "c", "cpp"]
Standards = Annotated[list[StandardFilter] | None, Field(
    description="Standards to map findings to, overriding the profile's `standards` (default "
                "profile: cert). misra-c-2012 applies to .c files (adds the cppcheck MISRA addon); "
                "misra-cpp-2023 and autosar-cpp14 to C++ files. Example: [\"cert\", \"misra\"].",
    examples=[["cert"], ["misra-c-2012"], ["cert", "autosar"]])]
CATEGORY = Literal["any", "API", "ARR", "CON", "CTR", "DCL", "ENV", "ERR", "EXP", "FIO", "FLP",
                   "INT", "MEM", "MSC", "OOP", "POS", "PRE", "SIG", "STR", "WIN"]


def _opt(v: str) -> str | None:
    return None if v == "any" else v


# ---------------------------------------------------------------- output models
class _Out(BaseModel):
    model_config = ConfigDict(extra="allow")


class RuleList(_Out):
    count: int = Field(description="Number of rules matching the filters, before `limit`.")
    truncated: bool = Field(description="True when count > limit and `rules` was cut.")
    rules: list[dict[str, Any]] = Field(description=(
        "Rule summaries: id, standard, title, lang (c|cpp), kind (rule|recommendation|directive), "
        "category, severity, likelihood, priority (P1-P27), level (L1-L3), detectable, url, "
        "coverage (tier over all mappings), coverage_runnable (tier with the pinned toolchain). "
        "MISRA/AUTOSAR entries add classification, category_name, decidability, enforcement and "
        "cert (related SEI CERT IDs); their title is our paraphrase, not the official headline."))


class SearchResult(_Out):
    query: str = Field(description="The query as received.")
    results: list[dict[str, Any]] = Field(description=(
        "Best match first. Same summary fields as list_rules (without coverage) plus `score`."))


class RuleRecord(_Out):
    id: str = Field(description="Canonical rule ID, e.g. EXP34-C or MISRA-C-2012-10.4.")
    title: str
    lang: str = Field(description="c or cpp.")
    kind: str = Field(description="rule, recommendation (CERT) or directive (MISRA).")
    category: str = Field(description="CERT three-letter category, or the MISRA/AUTOSAR section number.")
    url: str | None = Field(description="Rule page on the SEI CERT site, or the MISRA/AUTOSAR publication page.")
    standard: str = Field(description="cert-c, cert-cpp, misra-c-2012, misra-cpp-2023 or autosar-cpp14.")
    cwe: list[str] = Field(description="Related CWE IDs.")
    risk: dict[str, Any] | None = Field(description=(
        "CERT risk assessment: severity, likelihood, remediation, priority, level, "
        "detectable, repairable."))
    text: str = Field(description="Rule text as markdown; examples included unless include_examples=false. "
                                  "Copy `quote` values for validate_findings from here. MISRA/AUTOSAR: "
                                  "facts and our summary only, plus your licensed text when loaded.")
    examples: list[dict[str, Any]] = Field(description="Noncompliant/compliant example pairs; [] when include_examples=false.")
    coverage: dict[str, Any] = Field(description="tier, tier_runnable, tier_extended and checkers[] {tool, checker, specific, available}.")
    profile: dict[str, Any] = Field(description="name, override (severity/priority/note), disabled reason or null, idioms[].")


class Finding(_Out):
    rule_id: str = Field(description="Rule ID (SEI CERT, or MISRA/AUTOSAR when those standards are selected).")
    file: str = Field(description="Absolute path of the file.")
    line: int = Field(description="1-based line.")
    severity: Literal["error", "warning", "note"]
    message: str = Field(description="Analyzer message.")
    confidence: float = Field(description="0-1.")


class CheckResult(_Out):
    profile: str = Field(description="Profile used.")
    files: list[str] = Field(description="Files analysed (absolute paths).")
    findings: list[Finding] = Field(description=(
        "Sorted by severity, priority, confidence. Each also has lang, col, priority, level, "
        "tool, checker, title, cert_severity, also_found_by[], note, url."))
    tools: list[dict[str, Any]] = Field(description=(
        "Per analyzer: tool, available, version, files, raw_findings, parse_errors, "
        "files_with_errors[], timed_out[], notes[], status ('ok' | 'partial' = some files did not compile or timed out | 'missing')."))
    warnings: list[str] = Field(description="One line per analyzer that could not fully analyse its input (compile errors or timeouts); non-empty means the result is incomplete.")
    notes: list[str] = Field(description="Engine notes, e.g. 'no C/C++ files selected'.")
    suppressed_count: int = Field(description="Findings hidden by the profile or inline ignores.")
    summary: dict[str, Any] = Field(description="total, by_severity {error, warning, note}, top_rules [[rule_id, count], ...]. Counts only findings left after the baseline filter.")
    baseline: dict[str, Any] | None = Field(None, description=(
        "Present only with baseline_path: path, entries (in the file), new (findings returned), "
        "baselined (findings hidden because they match an entry), fixed (entries in analysed files "
        "with no matching finding; null for check_diff, which sees only changed lines), "
        "fixed_entries[] (up to 50 {rule_id, file, line, message}) and note."))


class DiffCheckResult(CheckResult):
    changed_files: list[str] = Field(description="Every file in the diff, relative to root, including non-C/C++ files that were skipped.")
    root: str = Field(description="Absolute repository root used to resolve diff paths.")


class Explanation(_Out):
    rule: dict[str, Any] = Field(description="id, title, lang, category, url, severity, priority, level, cwe[], summary (first sentence of the rule), coverage (checker tier).")
    finding: dict[str, Any] = Field(description="Echo of the input: file, line, tool, checker, message, code (flagged line) and snippet (numbered lines around it, read from the file).")
    why: list[str] = Field(description="Reasons the finding matches the rule: checker mapping (rule-specific or general), message, APIs the rule discusses, identifiers shared with the CERT example, profile notes.")
    example: dict[str, Any] | None = Field(description="Closest CERT example pair: index, similarity (token Jaccard 0-1), shared_tokens[], noncompliant {heading, code}, compliant {heading, code, text}; null when the rule has no example pair.")
    fix: dict[str, Any] = Field(description="summary (one-line advice), steps[] (ordered advice: follow the compliant example, API replacements, lines it adds), example_diff (unified diff noncompliant -> compliant), category_advice.")
    alternatives: list[dict[str, Any]] = Field(description="Next best example pairs {index, heading, score}; pass a different code snippet to steer the choice.")
    profile: str = Field(description="Profile used for notes and disabled rules.")


class Packet(_Out):
    instructions: str = Field(description="How to review the hunks and what makes a finding acceptable.")
    finding_schema: dict[str, Any] = Field(description="Fields each finding must have: rule_id, file, line, message, quote; optional severity, fix, confidence.")
    profile: str
    hunks: list[dict[str, Any]] = Field(description=(
        "file (absolute), start_line, end_line, code (line-numbered), idioms[] {id, hint}, "
        "candidate_rules[] {rule_id, title, tier, matched, severity, priority, level, "
        "profile_note, text (<= 3500 chars), url}, existing_findings[] {rule_id, line, checker}."))
    skipped_hunks: list[Any] = Field(description="[file, start_line, end_line] of hunks with no candidate rule.")
    static_findings: list[dict[str, Any]] = Field(description="Analyzer findings for the same scope; [] when run_static=false.")
    rule_database: str = Field(description="Commit of the bundled rule database.")


class Validation(_Out):
    accepted: list[dict[str, Any]] = Field(description="Grounded findings in the check_files finding shape plus quote and fix; pass to format_findings.")
    rejected: list[dict[str, Any]] = Field(description="{finding, reasons[]} for each rejected finding.")
    summary: dict[str, int] = Field(description="{accepted, rejected} counts.")


class Coverage(_Out):
    total: int = Field(description="Rules counted after the standard/lang/kind filters.")
    all_mappings: dict[str, int] = Field(description="Counts per tier using every upstream checker mapping.")
    runnable_toolchain: dict[str, int] = Field(description="Counts per tier using only the reference toolchain shipped in the Docker image: clang-tidy, Clang Static Analyzer, cppcheck and the bundled Semgrep rules.")
    extended_toolchain: dict[str, int] = Field(description="Counts per tier when the optional Infer and CodeQL (CERT query packs) analyzers are installed as well.")
    toolchain: dict[str, str] = Field(description="Pinned analyzer versions the tiers were computed for.")
    definitions: dict[str, str] = Field(description="Meaning of deterministic, partial and llm-only.")
    sources: dict[str, Any] = Field(description="Upstream mapping sources and commits.")


# ---------------------------------------------------------------- input models
class FindingIn(BaseModel):
    """A finding written from a build_review_packet hunk."""
    model_config = ConfigDict(extra="allow")
    rule_id: str = Field(description="A rule_id from the hunk's candidate_rules, e.g. EXP34-C.")
    file: str = Field(description="Path exactly as in the hunk's `file` field.")
    line: int = Field(ge=1, description="Line inside that hunk's start_line..end_line.")
    message: str = Field(description="What is wrong in this code and why it violates the rule.")
    quote: str | None = Field(None, description=(
        "Verbatim passage (>= 20 characters) copied from that rule's text or examples. Required for "
        "SEI CERT rules. For MISRA/AUTOSAR it is required only when a licensed rule-texts file is "
        "loaded (get_rule shows quote_required); otherwise omit it."))
    severity: Literal["error", "warning", "note"] | None = Field(None, description="Overrides the rule's default severity.")
    fix: str | None = Field(None, description="Compliant replacement code.")
    confidence: float | None = Field(None, ge=0, le=1, description="Defaults to 0.5.")


class FindingOut(BaseModel):
    """A finding produced by check_files, check_diff or validate_findings."""
    model_config = ConfigDict(extra="allow")
    rule_id: str
    file: str
    line: int = Field(ge=1)
    severity: Literal["error", "warning", "note"]
    priority: int
    level: str
    message: str
    tool: str
    checker: str


class FindingRef(BaseModel):
    """One finding to explain: a check_files/check_diff finding unchanged, or just a rule and a location."""
    model_config = ConfigDict(extra="allow")
    rule_id: str = Field(description="SEI CERT rule ID of the finding, e.g. ERR34-C.", examples=["ERR34-C"])
    file: str | None = Field(None, description="Absolute path of the source file; the flagged line and its neighbours are read from it.")
    line: int | None = Field(None, ge=1, description="1-based line of the finding in `file`.")
    code: str | None = Field(None, description="The flagged source line or a short snippet. Use when the file is not readable by the server; overrides the line read from `file`.")
    message: str | None = Field(None, description="Analyzer or reviewer message; its words also steer the example choice.")
    tool: str | None = Field(None, description="Analyzer that reported it (clang-tidy, clangsa, cppcheck), as in check_files output.")
    checker: str | None = Field(None, description="Checker name, e.g. cert-err34-c; used to say whether the mapping is rule-specific.")


class PacketIn(BaseModel):
    model_config = ConfigDict(extra="allow")
    hunks: list[dict[str, Any]] = Field(description="The packet's hunks; only file, start_line, end_line and candidate_rules[].rule_id are read.")


def _guard(fn):
    """Surface errors to the client: mcp 2.x hides messages of non-ToolError exceptions."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except ToolError:
            raise
        except FileNotFoundError as e:
            raise ToolError(f"{e}. Available profiles: {P.available()}") from e
        except Exception as e:                      # noqa: BLE001
            raise ToolError(f"{type(e).__name__}: {e}") from e
    return wrapper


def _exists(path: str) -> str:
    p = Path(path).expanduser()
    if not p.exists():
        raise ToolError(f"path not found: {path} (relative paths resolve against the server's "
                        f"working directory {Path.cwd()}; pass an absolute path)")
    return str(p)


def _repo_for_diff(repo: str, diff_text: str | None) -> str:
    """Repo root for diff mode: may not exist on disk when diff_text will materialize files."""
    p = Path(repo).expanduser()
    if diff_text:
        return str(p)
    return _exists(repo)


RO = dict(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def build_server() -> Any:
    kw: dict[str, Any] = {"instructions": INSTRUCTIONS}
    try:
        mcp = _Server(SERVER_NAME, website_url=WEBSITE, **kw)
    except TypeError:                               # older 1.x without website_url
        mcp = _Server(SERVER_NAME, **kw)

    # ------------------------------------------------------------ rule lookup
    @mcp.tool(
        title="List coding-standard rules by filter",
        annotations=ToolAnnotations(title="List coding-standard rules by filter", **RO),
        structured_output=True,
        description=(
            "List rules from the bundled databases, filtered by standard, language, category, "
            "kind, risk level, CERT detectability, MISRA/AUTOSAR classification or checker "
            "coverage. Default standard is SEI CERT C/C++ (388 rules and recommendations); "
            "standard='misra' or 'autosar' lists MISRA C:2012 (221), MISRA C++:2023 (178) or "
            "AUTOSAR C++14 (397) guidelines. Use to enumerate rules by structured criteria, e.g. "
            "all L1 C++ rules no checker detects or all mandatory MISRA C rules. Do not use for "
            "free-text lookup (use search_rules) or one rule's details (use get_rule). Reads "
            "bundled data only; fast. Returns summaries; `count` is the total before `limit`, so "
            "raise limit or narrow filters when `truncated` is true."))
    @_guard
    def list_rules(
        standard: Annotated[StandardFilter, Field(description=STANDARD_DOC)] = "cert",
        lang: Annotated[LANGS, Field(description="c = C rules (SEI CERT C, MISRA C), cpp = C++ rules (SEI CERT C++, MISRA C++, AUTOSAR).")] = "any",
        category: Annotated[CATEGORY, Field(description="SEI CERT three-letter category, e.g. EXP expressions, MEM memory, INT integers, STR strings, CON concurrency. Ignored for other standards' sections.")] = "any",
        kind: Annotated[Literal["any", "rule", "recommendation", "directive"], Field(description="rule = normative rule; recommendation = CERT advisory (C only); directive = MISRA directive.")] = "any",
        classification: Annotated[Classification, Field(description="MISRA/AUTOSAR classification; SEI CERT rules have none and are excluded when this is set.")] = "any",
        level: Annotated[Literal["any", "L1", "L2", "L3"], Field(description="CERT priority level; L1 is the most urgent.")] = "any",
        detectable: Annotated[bool | None, Field(description="CERT's own 'Detectable' flag (true = automatable in principle). Omit for both.")] = None,
        coverage: Annotated[Literal["any", "deterministic", "partial", "llm-only"], Field(description=(
            "Checker coverage tier: deterministic = a rule-specific checker exists; partial = only "
            "general checkers; llm-only = no checker, manual review needed. Matches either the "
            "all-mappings or the pinned-toolchain tier."))] = "any",
        limit: Annotated[int, Field(ge=1, le=400, description="Maximum summaries returned (each ~400 bytes).")] = 50,
    ) -> RuleList:
        return api.list_rules(_opt(lang), _opt(category), _opt(kind), _opt(level), detectable,
                              _opt(coverage), limit, standard, _opt(classification))

    @mcp.tool(
        title="Search coding-standard rules by keyword",
        annotations=ToolAnnotations(title="Search coding-standard rules by keyword", **RO),
        structured_output=True,
        description=(
            "Rank rules by keyword relevance to a free-text query: API names (strcpy, malloc, "
            "pthread_mutex_lock), concepts (integer overflow) or a rule ID in any accepted form "
            "(EXP34-C, misra-c2012-10.4, A5-2-2). Searches SEI CERT C/C++ by default; set "
            "`standard` for MISRA or AUTOSAR, where only our one-line summaries, section names "
            "and facts are searchable (plus licensed texts when loaded). Use when you know what "
            "the code does but not which rule applies. Do not use for structured filters (use "
            "list_rules) or to read a rule (use get_rule). Case-insensitive term counting, not "
            "semantic search; 1-character tokens are ignored and a query with no usable token "
            "returns an empty list. Reads bundled data only; fast."))
    @_guard
    def search_rules(
        query: Annotated[str, Field(min_length=2, description="Keywords separated by spaces; title hits weigh 8x body hits.", examples=["strcpy buffer", "signal handler", "EXP34-C"])],
        limit: Annotated[int, Field(ge=1, le=50, description="Maximum results.")] = 10,
        lang: Annotated[LANGS, Field(description="Restrict to C (c) or C++ (cpp) rules.")] = "any",
        standard: Annotated[StandardFilter, Field(description=STANDARD_DOC)] = "cert",
    ) -> SearchResult:
        return api.search_rules(query, limit, _opt(lang), standard)

    @mcp.tool(
        title="Get one coding-standard rule",
        annotations=ToolAnnotations(title="Get one coding-standard rule", **RO),
        structured_output=True,
        description=(
            "Return the full record of one rule. SEI CERT: text, noncompliant and compliant code "
            "examples, exceptions, risk assessment, CWE IDs, related MISRA/AUTOSAR guidelines "
            "(cross_references), the checkers that detect it, and how the profile adjusts or "
            "disables it. MISRA/AUTOSAR: classification, section, enforcement, related CERT rules, "
            "checkers and our one-line summary; the official text appears only when the user "
            "loaded a licensed rule-texts file (text_source, quote_required). Use before judging "
            "or explaining a finding, or to copy the verbatim `quote` validate_findings requires. "
            "Do not use to discover rules (use search_rules or list_rules). Reads bundled data "
            "only. CERT records are large (median ~10 KB, up to ~80 KB); set include_examples=false "
            "for text and risk only. An unknown ID returns an error listing close matches."))
    @_guard
    def get_rule(
        rule_id: RuleId,
        profile: Profile = "default",
        include_examples: Annotated[bool, Field(description="Include code examples in `text` and `examples`.")] = True,
    ) -> RuleRecord:
        d = api.explain_rule(rule_id, profile)
        if "error" in d:
            raise ToolError(f"{d['error']}; did you mean: {', '.join(d['did_you_mean']) or 'none'}")
        if not include_examples:
            d["examples"] = []
            d["text"] = R.rule_text(R.get(rule_id), include_examples=False)
        return d

    @mcp.tool(
        title="Summarize checker coverage per standard",
        annotations=ToolAnnotations(title="Summarize checker coverage per standard", **RO),
        structured_output=True,
        description=(
            "Count rules per detection tier: deterministic (a rule-specific checker exists, e.g. "
            "a clang-tidy cert-* alias or the cppcheck MISRA addon), partial (only general "
            "checkers map) and llm-only (no checker; manual review needed), for all checker "
            "mappings, for the pinned reference toolchain (clang-tidy and Clang Static Analyzer "
            "19.1.7, cppcheck 2.17.1, Semgrep with the bundled rules) and for the extended "
            "toolchain (plus Infer and the CodeQL CERT packs). SEI CERT by default; set "
            "`standard` for MISRA or AUTOSAR (adds by_standard and licensed_texts). Use to judge "
            "how much of a review static analysis can carry. Computed from bundled data; it "
            "does not probe the analyzers installed here (check_files reports those in tools[]). "
            "For one rule use get_rule; to list a tier's rules use list_rules with `coverage`."))
    @_guard
    def get_rule_coverage(
        standard: Annotated[StandardFilter, Field(description=STANDARD_DOC)] = "cert",
        lang: Annotated[LANGS, Field(description="Count only C (c) or C++ (cpp) rules.")] = "any",
        kind: Annotated[Literal["any", "rule", "recommendation", "directive"], Field(description="Count only rules, CERT recommendations or MISRA directives.")] = "any",
        include_ids: Annotated[bool, Field(description="Add rules_all_mappings, rules_runnable and rules_extended: rule ID lists per tier (~15 KB).")] = False,
    ) -> Coverage:
        return api.rule_coverage(_opt(lang), _opt(kind), include_ids, standard)

    # ------------------------------------------------------------ analysis
    @mcp.tool(
        title="Check C/C++ files for coding-standard violations",
        annotations=ToolAnnotations(title="Check C/C++ files for coding-standard violations", **RO),
        structured_output=True,
        description=(
            "Run clang-tidy, the Clang Static Analyzer and cppcheck (plus Semgrep and Infer when "
            "installed, CodeQL on request; see `tools`) on a C/C++ file or a "
            "directory (recursive) and return every finding mapped to SEI CERT rule IDs, or to "
            "MISRA C:2012 / MISRA C++:2023 / AUTOSAR C++14 IDs when `standards` (or the profile) "
            "selects them; MISRA C adds the cppcheck MISRA addon on .c files. Use for "
            "whole-file or whole-tree audits; for a change set use check_diff, which keeps only "
            "changed lines. Runs the analyzers as local subprocesses (4 in parallel, 300 s "
            "timeout per file and tool) and writes no files. Takes under a second per small file "
            "but minutes for large trees. Pass `compdb` when the project has a compilation "
            "database; without it flags are guessed and project headers are often missing. A "
            "tools[].status of 'partial' or non-empty `warnings` means some files did not "
            "compile or timed out, so an empty result is not proof. With `baseline_path`, "
            "findings already in the baseline are hidden and `baseline` reports new, baselined "
            "and fixed counts."))
    @_guard
    def check_files(
        path: Annotated[str, Field(description="Absolute path of a C/C++ file or a directory to scan recursively. Files are picked by the profile's extensions and exclude_paths.", examples=["/home/me/proj/src/buf.c", "/home/me/proj/src"])],
        profile: Profile = "default",
        compdb: Compdb = None,
        root: Annotated[str | None, Field(description="Absolute project root: adds root/src, root/include and similar as include paths, enables compdb auto-detection, and is the base for the profile's path globs.")] = None,
        lang: Annotated[LANGS, Field(description="Analyse only .c files (c) or only C++ files (cpp).")] = "any",
        tools: Tools = None,
        min_confidence: MinConfidence = 0.0,
        include_suppressed: IncludeSuppressed = False,
        standards: Standards = None,
        baseline_path: BaselinePath = None,
    ) -> CheckResult:
        return api.check_file(_exists(path), profile, _opt(lang), compdb, root, list(tools) if tools else None,
                              min_confidence, include_suppressed, standards=standards,
                              baseline=_exists(baseline_path) if baseline_path else None)

    @mcp.tool(
        title="Check changed C/C++ lines for coding-standard violations",
        annotations=ToolAnnotations(title="Check changed C/C++ lines for coding-standard violations", **RO),
        structured_output=True,
        description=(
            "Run the check_files analyzers on the C/C++ files of a change and keep only findings "
            "on added or modified lines, mapped to the same standards (`standards` or the "
            "profile; SEI CERT by default). The change is `base`..`head` in the git repo at `repo`, "
            "`base` against the working tree when head is omitted, or a pasted unified diff "
            "(`diff_text`, paths relative to repo). Use for pull-request or pre-commit review; for "
            "whole files use check_files. Runs `git diff` and the analyzers locally; writes "
            "nothing. For git refs, files must exist at `head` or line numbers will not match. "
            "With `diff_text`, files are reconstructed in a private temporary tree (the repo on disk "
            "is never modified). Check "
            "tools[].status and `warnings` before trusting an empty result. `baseline_path` hides "
            "findings recorded in a baseline file (fixed is not computed in diff scope)."))
    @_guard
    def check_diff(
        repo: Annotated[str, Field(description="Absolute path of the git checkout; diff paths are resolved against it.", examples=["/home/me/ceph"])],
        base: Annotated[str | None, Field(description="Base git ref (branch, tag or SHA). Required unless diff_text is given.", examples=["origin/main", "HEAD~1"])] = None,
        head: Annotated[str | None, Field(description="Head git ref. Omit to compare base with the working tree (uncommitted changes included).")] = None,
        diff_text: Annotated[str | None, Field(description="Unified diff text (git diff format, a/ b/ prefixes allowed). Overrides base and head.")] = None,
        profile: Profile = "default",
        compdb: Compdb = None,
        tools: Tools = None,
        min_confidence: MinConfidence = 0.0,
        include_suppressed: IncludeSuppressed = False,
        standards: Standards = None,
        baseline_path: BaselinePath = None,
        diff_context: Annotated[int, Field(ge=0, le=50,
                                           description="Also report findings within this many lines "
                                           "of a changed line (confidence scaled by 0.85).")] = 0,
    ) -> DiffCheckResult:
        if not (diff_text or base):
            raise ToolError("provide base (git ref) or diff_text")
        return api.check_diff(_repo_for_diff(repo, diff_text), base, head, diff_text, profile, compdb,
                              list(tools) if tools else None, min_confidence, include_suppressed,
                              standards=standards,
                              baseline=_exists(baseline_path) if baseline_path else None,
                              diff_context=diff_context)

    @mcp.tool(
        title="Explain a SEI CERT finding and suggest a fix",
        annotations=ToolAnnotations(title="Explain a SEI CERT finding and suggest a fix", **RO),
        structured_output=True,
        description=(
            "Explain one finding: a short rule summary, why the finding matches the rule (checker "
            "mapping, APIs, shared identifiers), the rule's noncompliant/compliant example pair "
            "most similar to the flagged code (token overlap), a unified diff between them, and "
            "concrete fix steps derived from that compliant example plus per-API and per-category "
            "advice. Use after check_files or check_diff when you need to explain or fix a "
            "finding; pass the finding object unchanged, or rule_id with file and line, or with a "
            "code snippet. Use get_rule instead for the full rule text and all examples, and "
            "validate_findings (not this tool) to check that a manually written finding is "
            "grounded. Deterministic and offline: reads only the bundled rules and the named "
            "file. An unknown rule_id returns an error listing close matches."))
    @_guard
    def explain_finding(
        finding: Annotated[FindingRef, Field(description="The finding: an item of check_files/check_diff `findings` as is, or {rule_id, file, line} or {rule_id, code}.")],
        profile: Profile = "default",
        context_lines: Annotated[int, Field(ge=0, le=20, description="Lines shown around the flagged line in finding.snippet (and used as fallback tokens when the line is blank).")] = 3,
    ) -> Explanation:
        f = finding.model_dump(exclude_none=True)
        if f.get("file") and not Path(f["file"]).expanduser().exists() and not f.get("code"):
            raise ToolError(f"path not found: {f['file']} (pass an absolute path, or `code` with the flagged line)")
        d = api.explain_finding(f, profile, context_lines)
        if "error" in d:
            raise ToolError(f"{d['error']}; did you mean: {', '.join(d['did_you_mean']) or 'none'}")
        return d

    # ------------------------------------------------------------ manual review layer
    @mcp.tool(
        title="Build a SEI CERT review packet",
        annotations=ToolAnnotations(title="Build a SEI CERT review packet", **RO),
        structured_output=True,
        description=(
            "Build a packet for reviewing code against SEI CERT rules that analyzers cannot "
            "decide: code hunks, each with up to max_rules_per_hunk candidate rules (picked by "
            "token/API heuristics and profile idioms, rules fully covered by a specific checker "
            "left out) and their text excerpts. Diff mode (`repo` plus `base` or `diff_text`): "
            "changed lines with 3 lines of context. Path mode (`path`): whole files. Hunks are cut "
            "into 60-line windows. Use after check_diff or check_files; judge each hunk, then send "
            "your findings to validate_findings. Read-only; run_static=true also runs the "
            "analyzers (same cost as check_diff/check_files) to mark lines already reported. "
            "Output is large, roughly 5-25 KB per hunk."))
    @_guard
    def build_review_packet(
        path: Annotated[str | None, Field(description="Path mode: absolute path of a file or directory. Ignored when diff mode applies.")] = None,
        repo: Annotated[str | None, Field(description="Diff mode: absolute path of the git checkout.")] = None,
        base: Annotated[str | None, Field(description="Diff mode: base git ref; required with repo unless diff_text is given.")] = None,
        head: Annotated[str | None, Field(description="Diff mode: head git ref; omit for the working tree.")] = None,
        diff_text: Annotated[str | None, Field(description="Diff mode: unified diff text, paths relative to repo.")] = None,
        profile: Profile = "default",
        run_static: Annotated[bool, Field(description="Also run the analyzers and list their findings per hunk so they are not repeated. Set false if you already ran check_diff/check_files.")] = True,
        compdb: Compdb = None,
        max_rules_per_hunk: Annotated[int | None, Field(ge=1, le=20, description="Candidate rules per hunk. Omit to use the profile's value (6 in both bundled profiles).")] = None,
        standards: Standards = None,
        tools: Tools = None,
        min_confidence: Annotated[float, Field(ge=0.0, le=1.0,
                                               description="Minimum confidence for bundled static analysis when run_static is true.")] = 0.0,
        diff_context: Annotated[int, Field(ge=0, le=50,
                                           description="Lines around a change to include in static analysis (confidence * 0.85).")] = 0,
    ) -> Packet:
        if not (path or (repo and base) or diff_text):
            raise ToolError("provide path, or repo with base or diff_text")
        if repo and not diff_text:
            _exists(repo)
        elif path:
            path = _exists(path)
        return api.review_packet(path, repo, base, head, diff_text, profile, run_static, compdb,
                                 max_rules_per_hunk, standards=standards,
                                 tools=list(tools) if tools else None, min_confidence=min_confidence,
                                 diff_context=diff_context)

    @mcp.tool(
        title="Validate manual SEI CERT findings",
        annotations=ToolAnnotations(title="Validate manual SEI CERT findings", **RO),
        structured_output=True,
        description=(
            "Accept or reject findings written from a build_review_packet review, with reasons. "
            "A finding passes only if its rule_id exists (C++ rules are rejected on .c files, "
            "MISRA C rules on C++ files), its quote is a passage of 20+ characters found in that "
            "rule's text or examples (case, whitespace, curly quotes and markdown are normalised; "
            "MISRA/AUTOSAR need a quote only when a licensed rule-texts file is loaded, otherwise "
            "accepted findings carry grounding='rule-id-only'), it has a file, a line "
            ">= 1 and a message, and the profile does not disable the rule. With `packet`, the "
            "line must also fall inside a hunk whose candidate_rules include the rule. Use on "
            "every manual finding before format_findings; check_files and check_diff output needs "
            "no validation. Pure computation on the arguments; reads no files."))
    @_guard
    def validate_findings(
        findings: Annotated[list[FindingIn], Field(description="Findings to check; an empty list is valid.")],
        packet: Annotated[PacketIn | None, Field(description="The build_review_packet result (or just {hunks}) to enforce hunk and candidate-rule bounds. Strongly recommended.")] = None,
        profile: Profile = "default",
    ) -> Validation:
        items = [f.model_dump(exclude_none=True) for f in findings]
        pk = packet.model_dump() if packet else None
        return api.validate_findings(items, pk, profile)

    @mcp.tool(
        title="Draft PR comment with hints and style nits",
        annotations=ToolAnnotations(title="Draft PR comment with hints and style nits", **RO),
        structured_output=True,
        description=(
            "Build a single markdown PR comment from `check_diff` output and "
            "`build_review_packet`: static tool summary, heuristic candidate-rule table, "
            "Ceph idiom hints, CodingStyle nits, and optional functional bullets. "
            "Does not post anywhere."))
    @_guard
    def format_pr_review(
        check_result: Annotated[dict[str, Any] | None, Field(description="Full object returned by check_diff (tools, findings, warnings, summary).")] = None,
        packet: Annotated[dict[str, Any] | None, Field(description="Result from build_review_packet (needs `hunks`).")] = None,
        title: Annotated[str | None, Field(description="Heading for the comment, e.g. the PR title.")] = None,
        scope: Annotated[str | None, Field(description="One line: merge-base..head and file list.")] = None,
        profile: Profile = "ceph",
        functional_notes: Annotated[list[str] | None, Field(description="Extra functional review bullets; omit to auto-suggest from packet code.")] = None,
        root: Annotated[str | None, Field(description="Repo root for relative paths in the markdown.")] = None,
        github_footer: Annotated[str | None, Field(description="Append collapsible footer: pull_request_target, mcp, or github-action. Omit to skip.")] = None,
    ) -> dict[str, Any]:
        return api.format_pr_review(
            title=title, scope=scope, profile=profile,
            check_result=check_result, packet=packet,
            functional_notes=functional_notes, root=root,
            github_footer=github_footer,
        )

    @mcp.tool(
        title="Review a PR change (static + hints + draft comment)",
        annotations=ToolAnnotations(title="Review a PR change (static + hints + draft comment)", **RO),
        structured_output=True,
        description=(
            "Run check_diff on `base`..`head`, build_review_packet for heuristic hints, "
            "and format_pr_review into one markdown comment (static table, candidate rules, "
            "idioms, style nits, functional bullets). Does not post. Prefer this over three "
            "separate calls. profile ceph auto-builds synthetic compdb when needed."))
    @_guard
    def review_pr(
        repo: Annotated[str, Field(description="Absolute path of the git checkout.", examples=["/home/me/ceph"])],
        base: Annotated[str, Field(description="Base git ref (merge-base or target branch SHA).", examples=["origin/main"])],
        head: Annotated[str | None, Field(description="Head ref (PR branch). Default: working tree.")] = None,
        profile: Profile = "ceph",
        title: Annotated[str | None, Field(description="PR title for the comment heading.")] = None,
        scope: Annotated[str | None, Field(description="Optional scope line; auto-generated when omitted.")] = None,
        compdb: Compdb = None,
        tools: Tools = None,
        min_confidence: MinConfidence = 0.5,
        standards: Standards = None,
        baseline_path: BaselinePath = None,
        diff_context: Annotated[int | None, Field(ge=0, le=50, description="Omit to use profile default (ceph: 3).")] = None,
        functional_notes: Annotated[list[str] | None, Field(description="Extra functional bullets for the comment.")] = None,
        github_footer: Annotated[
            str | None,
            Field(description="Append collapsible footer: pull_request_target, mcp, github-action. Omit when drafting for manual paste."),
        ] = None,
    ) -> dict[str, Any]:
        return api.review_pr(
            _exists(repo), base, head, profile=profile, title=title, scope=scope,
            compdb=_exists(compdb) if compdb else None,
            tools=list(tools) if tools else None,
            min_confidence=min_confidence, standards=standards,
            baseline=_exists(baseline_path) if baseline_path else None,
            diff_context=diff_context, functional_notes=functional_notes,
            github_footer=github_footer,
        )

    @mcp.tool(
        title="Format SEI CERT findings as a report",
        annotations=ToolAnnotations(title="Format SEI CERT findings as a report", **RO),
        description=(
            "Render findings as a report or review payload without sending it. style: markdown "
            "(string); github (object for POST /repos/{owner}/{repo}/pulls/{n}/reviews, event "
            "COMMENT, one comment per finding); gitlab (array of merge-request discussion bodies; "
            "position SHAs are placeholders to fill from diff_refs); sarif (SARIF 2.1.0 object); "
            "codequality (GitLab Code Quality array); gitlab-sast (GitLab SAST report object). "
            "Use as the last step, then show drafted comments to the user before anyone posts "
            "them. Pass findings unchanged from check_files/check_diff `findings` or "
            "validate_findings `accepted`. Pure formatting: no files, network or posting."))
    @_guard
    def format_findings(
        findings: Annotated[list[FindingOut], Field(description="Findings exactly as returned by check_files, check_diff (findings) or validate_findings (accepted).")],
        style: Annotated[Literal["markdown", "github", "gitlab", "sarif", "codequality", "gitlab-sast"], Field(description="Output format; see the tool description for each shape.")] = "markdown",
        root: Annotated[str | None, Field(description="Absolute repository root; file paths in the output are made relative to it. Omit and paths become relative to the server's working directory.")] = None,
        warnings: Annotated[list[str] | None, Field(description="`warnings` from check_files/check_diff; shown as a partial-analysis notice in markdown, github and sarif.")] = None,
    ) -> Any:
        from . import formatters
        items = [f.model_dump() for f in findings]
        return formatters.format_review(items, style, root, warnings)

    # ------------------------------------------------------------ resources and prompts
    @mcp.resource("rule://{rule_id}", mime_type="text/markdown")
    def rule_resource(rule_id: str) -> str:
        """Text of one SEI CERT rule as markdown, e.g. rule://EXP34-C."""
        r = R.get(rule_id)
        if r is None:
            raise ValueError(f"unknown rule {rule_id}")
        return R.rule_text(r) + f"\n\nSource: {r['url']}\n"

    @mcp.resource("profile://{name}", mime_type="text/yaml")
    def profile_resource(name: str) -> str:
        """YAML of a bundled review profile, e.g. profile://ceph."""
        from .paths import profiles_dir
        p = profiles_dir() / f"{name}.yaml"
        if not p.exists():
            raise ValueError(f"unknown profile {name}; available: {P.available()}")
        return p.read_text(encoding="utf-8")

    @mcp.prompt()
    def cert_review(target: str = "the current change", profile: str = "default") -> str:
        """Review code against SEI CERT C/C++."""
        return _prompt(target, profile, ceph=False)

    @mcp.prompt()
    def ceph_review(target: str = "the current change") -> str:
        """Review Ceph code against SEI CERT with Ceph idioms taken into account."""
        return _prompt(target, "ceph", ceph=True)

    return mcp


def _prompt(target: str, profile: str, ceph: bool) -> str:
    extra = ("Ceph context: ceph_assert is always active but is for invariants, not input validation; "
             "dout/ldout are stream based; locks are ceph::mutex (lockdep); RefCountedObject uses "
             "intrusive refs; crimson/asio callbacks outlive their frames. Read the profile://ceph "
             "resource for details.\n") if ceph else ""
    return (f"Review {target} against the SEI CERT C and C++ standards using the cert-review tools "
            f"(profile '{profile}').\n{extra}"
            "1. Prefer review_pr (or check_diff + build_review_packet + format_pr_review) for changes. "
            "Keep findings with confidence >= 0.5; mention partial tools in the summary.\n"
            "2. Show the format_pr_review markdown to the user for PR comments; never post without approval.\n"
            "3. For extra manual review: judge build_review_packet hunks; validate_findings on "
            "any hand-written findings; format_findings for line-by-line CERT violations only.")


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
