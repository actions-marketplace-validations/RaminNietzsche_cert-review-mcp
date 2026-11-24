"""Draft PR review bodies: static summary, heuristic hints, and style nits."""
from __future__ import annotations

import os
import re
from collections import OrderedDict
from typing import Any

from . import __version__

MARKER = "<!-- cert-review -->"

FOOTER_VIA_LABELS = {
    "pull_request_target": "pull_request_target",
    "mcp": "MCP",
    "github-action": "GitHub Action",
}


def github_footer_markdown(*, via: str = "pull_request_target") -> str:
    """Collapsible attribution for automated PR comments (Actions / MCP)."""
    label = FOOTER_VIA_LABELS.get(via, via)
    return (
        "\n<details>\n"
        "<summary>cert-review-mcp · auto-generated</summary>\n\n"
        "Report drafted with **[cert-review-mcp](https://github.com/RaminNietzsche/cert-review-mcp)** "
        f"(`{label}`). Findings are candidates; project QA and human review still apply.\n\n"
        "</details>\n"
    )

_STYLE_CHECKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bif\("), "Prefer `if (` — Ceph CodingStyle spacing after keywords."),
    (re.compile(r"\bfor\("), "Prefer `for (` — spacing after keywords."),
    (re.compile(r"\bwhile\("), "Prefer `while (` — spacing after keywords."),
    (re.compile(r"\bswitch\("), "Prefer `switch (` — spacing after keywords."),
    (re.compile(r" , "), "Avoid a space *before* comma in parameter lists (`foo, bar`)."),
    (re.compile(r",[^\s)\]]"), "Add a space after `,` in parameter lists where the style file expects it."),
)

def _functional_notes_from_packet(packet: dict[str, Any] | None) -> list[str]:
    notes: list[str] = []
    if not packet:
        return notes
    text = " ".join((h.get("code") or "") for h in packet.get("hunks") or [])
    if "from_remote_zone" in text:
        notes.append(
            "Trace `from_remote_zone` vs local writes: exclusivity on `write_name`, "
            "`-EEXIST` when a name object exists, and propagating `r` on sync retry paths."
        )
    if "metadata" in text.lower() and "sync" in text.lower():
        notes.append(
            "Metadata/multisite QA: confirm behaviour matches existing sync expectations."
        )
    if any("rgw/" in (h.get("file") or "") for h in packet.get("hunks") or []):
        if not notes:
            notes.append(
                "Exercise the relevant RGW or multisite tests if this PR changes on-disk "
                "or sync-visible behaviour."
            )
    return notes


def style_nits_in_text(code: str, path: str) -> list[dict[str, Any]]:
    """Lightweight CodingStyle nits on hunk text (heuristic, not authoritative)."""
    if not code or path.endswith((".py", ".rst", ".md", ".yaml", ".yml")):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        for pat, msg in _STYLE_CHECKS:
            if pat.search(line) and msg not in seen:
                seen.add(msg)
                out.append({"line": i, "message": msg, "excerpt": stripped[:120]})
    return out


def _sanitize_warning(msg: str) -> str:
    """Shorten temp diff-workspace paths to `src/...` in warning lines."""

    def short(m: re.Match[str]) -> str:
        return f"`{m.group(1)}`"

    return re.sub(r"(?:/private)?/[^\s:]+/(src/\S+)", short, msg)


def _rel(path: str, root: str | None) -> str:
    normalized = path.replace("\\", "/")
    m = re.search(r"(src/.+)$", normalized)
    if m:
        return m.group(1)
    if root:
        try:
            return os.path.relpath(path, root)
        except ValueError:
            return path
    return path


def _tool_rows(check: dict[str, Any]) -> list[tuple[str, str]]:
    rows = []
    for t in check.get("tools") or []:
        st = t.get("status") or ("ok" if t.get("available", True) else "missing")
        detail = f"{st}"
        if t.get("parse_errors"):
            detail += f" ({t['parse_errors']} parse error(s))"
        rows.append((t.get("tool", "?"), detail))
    return rows


def _summarize_hunks(packet: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for h in packet.get("hunks") or []:
        rules = h.get("candidate_rules") or []
        idioms = [i.get("id") for i in (h.get("idioms") or []) if i.get("id")]
        rows.append({
            "file": _rel(h.get("file", ""), None),
            "start": h.get("start_line"),
            "end": h.get("end_line"),
            "rule_ids": [c.get("rule_id") for c in rules if c.get("rule_id")],
            "rule_titles": {c["rule_id"]: c.get("title", "")[:80] for c in rules if c.get("rule_id")},
            "idioms": idioms,
            "code": h.get("code") or "",
        })
    return rows


def _idiom_hints(packet: dict[str, Any]) -> list[dict[str, str]]:
    seen: OrderedDict[str, str] = OrderedDict()
    for h in packet.get("hunks") or []:
        for i in h.get("idioms") or []:
            iid = i.get("id")
            if iid and iid not in seen:
                seen[iid] = " ".join((i.get("hint") or "").split())
    return [{"id": k, "hint": v} for k, v in seen.items() if v]


def pr_review_markdown(
    *,
    title: str | None = None,
    scope: str | None = None,
    profile: str = "ceph",
    check_result: dict[str, Any] | None = None,
    packet: dict[str, Any] | None = None,
    functional_notes: list[str] | None = None,
    root: str | None = None,
    github_footer: str | bool | None = None,
) -> str:
    """Markdown PR comment: static table + heuristic hints + style nits."""
    find = (check_result or {}).get("findings") or []
    warnings = (check_result or {}).get("warnings") or []
    n_cert = len([f for f in find if f.get("rule_id")])
    prof = profile
    ver = __version__
    lines = [MARKER, ""]
    hdr = title or "cert-review"
    lines.append(f"## {hdr} (profile `{prof}`, v{ver})")
    lines.append("")
    if scope:
        lines.append(f"**Scope:** {scope}")
        lines.append("")

    lines.append("### Static (changed lines)")
    lines.append("")
    lines.append("| Layer | Result |")
    lines.append("|-------|--------|")
    cert_line = "**none**" if n_cert == 0 else f"**{n_cert}** finding(s)"
    lines.append(f"| CERT findings (confidence ≥ 0.5 on changed lines) | {cert_line} |")
    for tool, detail in _tool_rows(check_result or {}):
        lines.append(f"| `{tool}` | {detail} |")
    if packet:
        nh = len(packet.get("hunks") or [])
        nc = sum(len(h.get("candidate_rules") or []) for h in (packet.get("hunks") or []))
        lines.append(f"| `build_review_packet` (heuristic) | {nh} hunk(s), {nc} candidate rule refs — not violations |")
    lines.append("")

    if warnings:
        lines.append("**Warnings:**")
        for w in warnings:
            lines.append(f"- {_sanitize_warning(w)}")
        lines.append("")

    k_rows = _summarize_hunks(packet or {})
    if k_rows:
        lines.append("### Heuristic hints (`build_review_packet`)")
        lines.append("")
        lines.append("Not violations — areas worth a manual pass:")
        lines.append("")
        lines.append("| Location | CERT areas surfaced | Ceph idiom hints |")
        lines.append("|----------|---------------------|------------------|")
        for row in k_rows:
            loc = f"`{_rel(row['file'], root)}` L{row['start']}–{row['end']}"
            rules = ", ".join(row["rule_ids"][:6])
            if len(row["rule_ids"]) > 6:
                rules += ", …"
            idi = ", ".join(f"`{x}`" for x in row["idioms"]) or "—"
            lines.append(f"| {loc} | {rules or '—'} | {idi} |")
        lines.append("")

        idiom_blocks = _idiom_hints(packet or {})
        if idiom_blocks:
            lines.append("**Idiom notes (from profile):**")
            lines.append("")
            for ib in idiom_blocks:
                lines.append(f"- **`{ib['id']}`:** {ib['hint'][:500]}{'…' if len(ib['hint']) > 500 else ''}")
            lines.append("")

    all_nits: list[dict[str, Any]] = []
    for row in k_rows:
        for nit in style_nits_in_text(row["code"], row["file"]):
            all_nits.append({**nit, "file": row["file"], "hunk_start": row["start"]})
    if all_nits:
        lines.append("### Style nits (CodingStyle — heuristic)")
        lines.append("")
        by_msg: OrderedDict[str, list[str]] = OrderedDict()
        for n in all_nits:
            by_msg.setdefault(n["message"], []).append(
                f"`{_rel(n['file'], root)}` (hunk ~L{n['hunk_start']})")
        for msg, where in by_msg.items():
            lines.append(f"- {msg} ({'; '.join(where[:3])}{'…' if len(where) > 3 else ''})")
        lines.append("")

    fn = (
        functional_notes
        if functional_notes is not None
        else _functional_notes_from_packet(packet)
    )
    if fn:
        lines.append("### Suggested functional review")
        lines.append("")
        for note in fn:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("### Bottom line")
    lines.append("")
    if n_cert == 0:
        lines.append(
            "No CERT blocker on changed lines from this static pass; "
            "project QA and human review of sync/metadata paths still apply."
        )
    else:
        lines.append(
            f"{n_cert} CERT finding(s) on changed lines — review each before merge."
        )
    lines.append("")
    body = "\n".join(lines)
    if github_footer:
        via = "pull_request_target" if github_footer is True else str(github_footer)
        body += github_footer_markdown(via=via)
    return body