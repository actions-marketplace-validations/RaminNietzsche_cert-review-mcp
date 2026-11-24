"""Shared API behind the CLI and the MCP server (all functions return plain data)."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import baseline as BL
from . import checkers_map as CM
from . import diffutil
from . import engine
from . import formatters
from . import packet as PK
from . import profiles as P
from . import rules as R
from . import toolrun as T
from . import validator as V
from .ceph_compdb import build_compdb, ensure_cached_compdb, is_ceph_tree, _git_run


def _git_rev(ceph: Path, ref: str) -> str | None:
    r = _git_run(ceph, "rev-parse", ref)
    return r.stdout.decode().strip() if r.returncode == 0 else None


def _resolve_compdb(
    compdb: str | None,
    prof: P.Profile,
    repo: str | None,
    *,
    changed_relpaths: list[str] | None = None,
    base: str | None = None,
    head: str | None = None,
    synthetic: bool | None = None,
) -> tuple[str | None, Path | None, list[str]]:
    """Pick compdb path; optionally build a temporary Ceph synthetic database."""
    if compdb:
        return compdb, None, []
    if not repo:
        return None, None, []
    repo_p = Path(repo).expanduser().resolve()
    if found := T.find_compdb(repo_p):
        return str(found), None, []
    want = prof.synthetic_compdb_default() if synthetic is None else synthetic
    if not want or not is_ceph_tree(repo_p):
        return None, None, []
    excl = prof.synthetic_compdb_excludes()
    git_ref = head or "HEAD"
    head_sha = _git_rev(repo_p, git_ref)
    checkout_sha = _git_rev(repo_p, "HEAD")
    same_ref = head_sha and checkout_sha and head_sha == checkout_sha
    if prof.synthetic_compdb_cache_default() and same_ref:
        cached = ensure_cached_compdb(repo_p, git_ref=git_ref, exclude=excl)
        if cached:
            n = len(json.loads((cached / "compile_commands.json").read_text()))
            return str(cached), None, [
                f"cached synthetic Ceph compile database ({n} file(s) at {git_ref}); "
                "refresh with `cert-review compdb --repo <ceph> --tracked`; "
                "a cmake build is still more accurate",
            ]
    tmp = Path(tempfile.mkdtemp(prefix="cert-review-ceph-compdb-"))
    git_diff = f"{base}...{git_ref}" if base else None
    build_compdb(
        repo_p, tmp, git_diff=git_diff, relpaths=changed_relpaths,
        git_ref=git_ref, exclude=excl,
    )
    n = len(json.loads((tmp / "compile_commands.json").read_text()))
    if n == 0:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None, [
            "no compile_commands.json under repo; synthetic Ceph compdb had no matching source files",
        ]
    return str(tmp), tmp, [
        f"synthetic Ceph compile database ({n} file(s)) — approximate flags; "
        "a real build (-DCMAKE_EXPORT_COMPILE_COMMANDS=ON) is more accurate",
    ]


def _remap_packet(packet: dict | None, check_result: dict | None, root: str | None) -> dict | None:
    if not packet:
        return packet
    ws = (check_result or {}).get("workspace")
    repo = (check_result or {}).get("root") or root
    if not ws or not repo:
        return packet
    import copy
    out = copy.deepcopy(packet)
    ws_p = Path(ws)
    for h in out.get("hunks") or []:
        if h.get("file"):
            h["file"] = _remap_workspace_paths([h["file"]], ws_p, repo)[0]
    return out


def format_pr_review(
    *,
    title: str | None = None,
    scope: str | None = None,
    profile: str = "ceph",
    check_result: dict | None = None,
    packet: dict | None = None,
    functional_notes: list[str] | None = None,
    root: str | None = None,
    github_footer: str | bool | None = None,
) -> dict:
    """Format a GitHub/GitLab-ready PR comment with static results, hints and style nits."""
    from . import pr_comment as PC

    pkt = _remap_packet(packet, check_result, root)
    body = PC.pr_review_markdown(
        title=title, scope=scope, profile=profile,
        check_result=check_result, packet=pkt,
        functional_notes=functional_notes, root=root or (check_result or {}).get("root"),
        github_footer=github_footer,
    )
    from . import __version__ as ver
    return {"markdown": body, "profile": profile, "version": ver}


def review_pr(
    repo: str,
    base: str,
    head: str | None = None,
    *,
    profile: str = "ceph",
    title: str | None = None,
    scope: str | None = None,
    compdb: str | None = None,
    tools: list[str] | None = None,
    min_confidence: float = 0.5,
    standards: Any = None,
    baseline: str | None = None,
    diff_context: int | None = None,
    functional_notes: list[str] | None = None,
    include_packet: bool = True,
    include_check: bool = True,
    github_footer: str | bool | None = None,
) -> dict:
    """One-shot PR review: check_diff + build_review_packet + format_pr_review."""
    prof = P.load(profile)
    ctx = prof.diff_context_default() if diff_context is None else diff_context
    ck = check_diff(
        repo, base, head, None, profile, compdb,
        tools, min_confidence, False, 4, 2, standards, baseline, ctx,
    )
    pkt = review_packet(
        None, repo, base, head, None, profile,
        run_static=False, compdb=compdb, standards=standards,
        tools=tools, min_confidence=min_confidence, diff_context=ctx,
    ) if include_packet else None
    if not scope:
        head_s = head or "HEAD"
        cf = ck.get("changed_files") or []
        cppish = [f for f in cf if Path(f).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}]
        extra = f" — {len(cppish)} C/C++ file(s)" if cppish else f" — {len(cf)} file(s)"
        scope = f"`{base}`..`{head_s}`{extra}"
    fr = format_pr_review(
        title=title, scope=scope, profile=profile,
        check_result=ck, packet=pkt, functional_notes=functional_notes, root=repo,
        github_footer=github_footer,
    )
    out: dict[str, Any] = {
        "markdown": fr["markdown"],
        "profile": profile,
        "version": fr["version"],
        "scope": scope,
        "cert_findings_on_diff": len(ck.get("findings") or []),
        "summary": ck.get("summary"),
        "warnings": ck.get("warnings"),
        "notes": ck.get("notes"),
    }
    if include_check:
        out["check_diff"] = ck
    if include_packet and pkt:
        out["review_packet"] = {
            "hunks": len(pkt.get("hunks") or []),
            "skipped_hunks": pkt.get("skipped_hunks"),
        }
    return out


def refresh_ceph_compdb(repo: str, *, tracked: bool = True, force: bool = False,
                        git_ref: str = "HEAD") -> dict:
    """Build or refresh `.cert-review/compdb-cache` under a Ceph checkout."""
    repo_p = Path(repo).expanduser().resolve()
    if not is_ceph_tree(repo_p):
        return {"error": "not a Ceph tree", "repo": str(repo_p)}
    prof = P.load("ceph")
    excl = prof.synthetic_compdb_excludes()
    if tracked:
        dest = ensure_cached_compdb(repo_p, git_ref=git_ref, exclude=excl, force=force)
    else:
        dest = None
    if not dest:
        return {"error": "no sources selected", "repo": str(repo_p)}
    n = len(json.loads((dest / "compile_commands.json").read_text()))
    meta = json.loads((dest / "meta.json").read_text())
    return {
        "repo": str(repo_p),
        "compdb": str(dest),
        "entries": n,
        "tree_id": meta.get("tree_id"),
        "current_link": str(repo_p / ".cert-review/compdb-cache/current"),
    }


def list_rules(lang: str | None = None, category: str | None = None, kind: str | None = None,
               level: str | None = None, detectable: bool | None = None,
               coverage: str | None = None, limit: int = 500, standard: Any = None,
               classification: str | None = None) -> dict:
    out = []
    for r in R.list_rules(lang=lang, category=category, kind=kind, level=level, detectable=detectable,
                          standard=standard, classification=classification):
        e = CM.rule_entry(r["id"])
        if coverage and e["tier_runnable"] != coverage and e["tier"] != coverage:
            continue
        s = R.summary(r)
        s["coverage"] = e["tier"]
        s["coverage_runnable"] = e["tier_runnable"]
        out.append(s)
    return {"count": len(out), "rules": out[:limit], "truncated": len(out) > limit}


def _guideline_record(r: dict, prof: P.Profile) -> dict:
    from . import ruletexts
    e = CM.rule_entry(r["id"])
    std = R.standard_of(r)
    lic = ruletexts.text_for(r["id"])
    return {
        "id": r["id"], "title": R.title(r), "lang": r["lang"], "kind": r["kind"],
        "category": r["category"], "url": R.url(r), "cwe": [], "risk": None,
        "text": R.rule_text(r), "exceptions": None, "examples": [],
        "automated_detection": None, "related_guidelines": None,
        "standard": std, "display_name": R.display_name(r), "local_id": r["local_id"],
        "classification": r["classification"], "category_name": r.get("category_name"),
        "summary": r.get("summary"), "decidability": r.get("decidability"),
        "enforcement": r.get("enforcement"), "target": r.get("target"),
        "cert": r.get("cert", []),
        "text_source": "licensed-file" if lic else "summary-only",
        "quote_required": bool(lic),
        "coverage": {"tier": e["tier"], "tier_runnable": e["tier_runnable"],
                     "checkers": [{k: c[k] for k in ("tool", "checker", "specific", "available")}
                                  | {"source": c.get("source")} for c in e["checkers"]]},
        "profile": {"name": prof.name, "override": prof.override(r["id"]),
                    "disabled": prof.disabled(r["id"]), "idioms": []},
        "source": {**R.guideline_info()["standards"].get(std, {}),
                   "data_sources": R.guideline_info()["sources"],
                   "notice": R.guideline_info()["notice"]},
    }


def related_guidelines_for_cert(cert_id: str) -> list[dict]:
    """MISRA/AUTOSAR guidelines that cite (or are cited by) a SEI CERT rule."""
    out = []
    for g in R.guidelines().values():
        for c in g.get("cert", []):
            if c["id"] == cert_id:
                out.append({"id": g["id"], "standard": g["standard"],
                            "name": R.display_name(g), "relation": c["relation"],
                            "source": c["source"]})
    return out


def explain_rule(rule_id: str, profile: str = "default") -> dict:
    r = R.get(rule_id)
    if r is None:
        near = [x["id"] for x in R.search(rule_id, 5, standard="all")]
        return {"error": f"unknown rule {rule_id}", "did_you_mean": near}
    prof = P.load(profile)
    if not R.is_cert(r):
        return _guideline_record(r, prof)
    e = CM.rule_entry(r["id"])
    return {
        "id": r["id"], "title": r["title"], "lang": r["lang"], "kind": r["kind"],
        "category": r["category"], "url": r["url"], "cwe": r["cwe"], "risk": r["risk"],
        "text": R.rule_text(r), "exceptions": r["exceptions"],
        "examples": r["examples"],
        "automated_detection": r["automated_detection"],
        "related_guidelines": r["related_guidelines"],
        "coverage": {"tier": e["tier"], "tier_runnable": e["tier_runnable"],
                     "tier_extended": e.get("tier_extended", e["tier_runnable"]),
                     "checkers": [{k: c[k] for k in ("tool", "checker", "specific", "available")}
                                  for c in e["checkers"]]},
        "profile": {"name": prof.name, "override": prof.override(r["id"]),
                    "disabled": prof.disabled(r["id"]),
                    "idioms": [i["id"] for i in prof.raw.get("idioms", []) if r["id"] in i["rules"]]},
        "source": R.source_info(),
        "standard": R.standard_of(r),
        "cross_references": related_guidelines_for_cert(r["id"]),
    }


def explain_finding(finding: dict, profile: str = "default", context_lines: int = 3) -> dict:
    from . import explain as EX
    return EX.explain(finding, profile, context_lines)


def write_baseline(result: dict, path: str, update: bool = False) -> dict:
    """Create or update a baseline file from a check_file/check_diff result."""
    root = BL.root_of(path)
    old = BL.load(path) if update and Path(path).expanduser().exists() else None
    data, stats = BL.update(old, result["findings"], result.get("files", []), root)
    BL.dump(data, Path(path).expanduser())
    stats["path"] = str(Path(path).expanduser().resolve())
    return stats


def search_rules(query: str, limit: int = 10, lang: str | None = None, standard: Any = None) -> dict:
    return {"query": query, "results": R.search(query, limit, lang, standard)}


def _collect(paths: list[str]) -> list[str]:
    return [str(Path(p).expanduser()) for p in paths]


def check_file(path: str | list[str], profile: str = "default", lang: str | None = None,
               compdb: str | None = None, root: str | None = None,
               tools: list[str] | None = None, min_confidence: float = 0.0,
               include_suppressed: bool = False, jobs: int = 4,
               max_rules_per_location: int = 2, standards: Any = None,
               baseline: str | None = None) -> dict:
    paths = [path] if isinstance(path, str) else list(path)
    res = engine.check(_collect(paths), profile, lang, compdb, root,
                       tuple(tools) if tools else None,
                       None, jobs, max_rules_per_location, min_confidence, include_suppressed,
                       standards)
    d = res.to_dict(include_suppressed)
    if baseline:
        BL.apply(d, baseline, scope="files")
    d["summary"] = summarize(d["findings"])
    return d


def _diff_text(repo: str | None, base: str | None, head: str | None, diff_text: str | None) -> str:
    if diff_text:
        return diff_text
    if not (repo and base):
        raise ValueError("provide diff_text, or repo and base (and optionally head)")
    return diffutil.git_diff(repo, base, head)


def _remap_workspace_paths(paths: list[str], workspace: Path, repo: str | None) -> list[str]:
    """Point analysis paths at the checkout, not the private diff worktree (for SARIF and filters)."""
    if not repo:
        return paths
    repo_p = Path(repo).expanduser().resolve()
    ws = workspace.resolve()

    def one(path: str) -> str:
        try:
            return str((repo_p / Path(path).resolve().relative_to(ws)).resolve())
        except ValueError:
            return path

    return [one(p) for p in paths]


def _remap_finding_files(findings: list[dict], workspace: Path, repo: str | None) -> None:
    for f in findings:
        f["file"] = _remap_workspace_paths([f["file"]], workspace, repo)[0]


def _diff_content_ref(repo: str | None, head: str | None, diff_text: str | None) -> str | None:
    """Git revision whose file contents match the diff's post-image (+ side)."""
    if diff_text or not repo:
        return None
    hint = Path(repo).expanduser()
    if not hint.is_dir() or not diffutil._is_git_repo(hint.resolve()):
        return None
    return head or "HEAD"


def check_diff(repo: str | None = None, base: str | None = None, head: str | None = None,
               diff_text: str | None = None, profile: str = "default",
               compdb: str | None = None, tools: list[str] | None = None,
               min_confidence: float = 0.0, include_suppressed: bool = False, jobs: int = 4,
               max_rules_per_location: int = 2, standards: Any = None,
               baseline: str | None = None, diff_context: int | None = None) -> dict:
    text = _diff_text(repo, base, head, diff_text)
    changed = diffutil.parse_unified_diff(text)
    ws = diffutil.prepare_diff_workspace(repo, text, content_ref=_diff_content_ref(repo, head, diff_text))
    cdb_tmp: Path | None = None
    try:
        root_p = ws.root
        root = str(root_p)
        prof = P.load(profile)
        ctx = prof.diff_context_default() if diff_context is None else diff_context
        repo_p = str(Path(repo).expanduser().resolve()) if repo else None
        cdb, cdb_tmp, cdb_notes = _resolve_compdb(
            compdb, prof, repo, changed_relpaths=sorted(changed), base=base, head=head)
        files = engine.select_files(list(ws.abs_changed()), prof, None, root_p)
        res = engine.check(files, prof, None, cdb, root,
                           tuple(tools) if tools else None,
                           ws.abs_changed(), jobs, max_rules_per_location, min_confidence,
                           include_suppressed, standards, diff_context=ctx,
                           compdb_search_root=repo_p)
        d = res.to_dict(include_suppressed)
        if repo:
            d["files"] = _remap_workspace_paths(d.get("files") or [], root_p, repo)
            _remap_finding_files(d["findings"], root_p, repo)
            if include_suppressed:
                _remap_finding_files(d.get("suppressed") or [], root_p, repo)
        if baseline:
            BL.apply(d, baseline, scope="diff")
        d["summary"] = summarize(d["findings"])
        d["changed_files"] = sorted(changed)
        d["root"] = str(Path(repo).expanduser().resolve()) if repo else root
        d["workspace"] = root
        if cdb:
            d["compdb"] = cdb
        if cdb_notes:
            d.setdefault("notes", []).extend(cdb_notes)
        return d
    finally:
        if cdb_tmp:
            shutil.rmtree(cdb_tmp, ignore_errors=True)
        ws.cleanup()


def review_packet(path: str | list[str] | None = None, repo: str | None = None,
                  base: str | None = None, head: str | None = None, diff_text: str | None = None,
                  profile: str = "default", run_static: bool = True, compdb: str | None = None,
                  max_rules_per_hunk: int | None = None, context_lines: int = 3,
                  standards: Any = None, tools: list[str] | None = None,
                  min_confidence: float = 0.0, diff_context: int | None = None) -> dict:
    prof = P.load(profile)
    existing: list[dict] = []
    max_hunk = (prof.raw.get("llm_review") or {}).get("max_hunk_lines", 60)
    if diff_text or (repo and base):
        text = _diff_text(repo, base, head, diff_text)
        ws = diffutil.prepare_diff_workspace(repo, text,
                                             content_ref=_diff_content_ref(repo, head, diff_text))
        cdb_tmp = None
        try:
            root = ws.root
            hunk_ctx = diffutil.hunks_with_context(text, context_lines)
            ranges = {str((root / k).resolve()): v for k, v in hunk_ctx.items()}
            ranges = {k: v for k, v in ranges.items() if Path(k).exists()}
            files = engine.select_files(list(ranges), prof, None, root)
            ranges = {k: v for k, v in ranges.items() if k in set(files)}
            if run_static and files:
                abs_changed = ws.abs_changed()
                sel = engine.select_files(list(abs_changed), prof, None, root)
                ctx = prof.diff_context_default() if diff_context is None else diff_context
                changed = diffutil.parse_unified_diff(text)
                cdb, cdb_tmp, cdb_notes = _resolve_compdb(
                    compdb, prof, repo, changed_relpaths=sorted(changed), base=base, head=head)
                res = engine.check(sel, prof, None, cdb, str(root),
                                   tuple(tools) if tools else None,
                                   abs_changed, 4, 2, min_confidence, False,
                                   standards, diff_context=ctx,
                                   compdb_search_root=repo)
                existing = res.to_dict()["findings"]
                pk_notes = cdb_notes
            else:
                pk_notes = []
            hunks = PK.build_hunks(ranges, max_hunk)
            pk = PK.build(hunks, prof, existing, max_rules_per_hunk)
            pk["static_findings"] = existing
            if pk_notes:
                pk["notes"] = pk_notes
            return pk
        finally:
            if cdb_tmp:
                shutil.rmtree(cdb_tmp, ignore_errors=True)
            ws.cleanup()
    if path:
        files = engine.select_files(_collect([path] if isinstance(path, str) else list(path)), prof)
        ranges = PK.whole_file_ranges(files)
        if run_static and files:
            existing = check_file(files, profile, compdb=compdb, standards=standards)["findings"]
    else:
        raise ValueError("provide path, or diff_text, or repo and base")
    hunks = PK.build_hunks(ranges, max_hunk)
    pk = PK.build(hunks, prof, existing, max_rules_per_hunk)
    pk["static_findings"] = existing
    return pk


def validate_findings(findings: list[dict] | str, packet: dict | None = None,
                      profile: str = "default") -> dict:
    import json
    if isinstance(findings, str):
        findings = json.loads(findings)
    if isinstance(findings, dict) and "findings" in findings:
        findings = findings["findings"]
    return V.validate(findings, packet, profile)


def rule_coverage(lang: str | None = None, kind: str | None = None, include_ids: bool = False,
                  standard: Any = None) -> dict:
    stds = R.expand_standards(standard)
    c = CM.coverage(lang, kind, stds)
    if not include_ids:
        c.pop("rules_all_mappings")
        c.pop("rules_runnable")
        c.pop("rules_extended")
    c["standards"] = list(stds)
    c["definitions"] = CM.info()["tier_definitions"]
    c["sources"] = CM.info()["sources"]
    if set(stds) - set(R.CERT_STANDARDS):
        from . import ruletexts
        g = R.guideline_info()
        c["definitions"] = {**c["definitions"],
                            "deterministic": c["definitions"]["deterministic"]
                            + "; for MISRA/AUTOSAR: a checker that reports exactly this guideline "
                              "(e.g. the cppcheck MISRA addon)"}
        c["sources"] = {**c["sources"], "guidelines": g["sources"]}
        c["toolchain"] = {**c["toolchain"], **{k: v for k, v in
                                               R._load_guidelines().get("toolchain_versions", {}).items() if v}}
        by_std = {}
        for s in stds:
            if s in R.CERT_STANDARDS:
                continue
            sc = CM.coverage(lang, kind, (s,))
            by_std[s] = {"total": sc["total"], "all_mappings": sc["all_mappings"],
                         "runnable_toolchain": sc["runnable_toolchain"],
                         "summaries": (g["standards"].get(s) or {}).get("summaries")}
        c["by_standard"] = by_std
        c["licensed_texts"] = {k: v for k, v in ruletexts.status().items() if k in stds}
    return c


def format_review(findings: list[dict] | str, style: str = "markdown", root: str | None = None) -> Any:
    import json
    if isinstance(findings, str):
        findings = json.loads(findings)
    if isinstance(findings, dict) and "findings" in findings:
        findings = findings["findings"]
    return formatters.format_review(findings, style, root)


def summarize(findings) -> dict:
    items = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
    by_sev: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in items:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1
    return {"total": len(items), "by_severity": by_sev,
            "top_rules": sorted(by_rule.items(), key=lambda x: -x[1])[:10]}
