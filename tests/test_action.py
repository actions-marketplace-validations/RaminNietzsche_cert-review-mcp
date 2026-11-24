"""GitHub Action entrypoint, action.yml and CI templates."""
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from cert_review import action, formatters as Fm, findings as F, profiles as P
from conftest import need_clang_tidy

ROOT = Path(__file__).resolve().parents[1]


def test_action_yml_structure():
    a = yaml.safe_load((ROOT / "action.yml").read_text())
    for i in ("profile", "mode", "base-ref", "include", "exclude", "compile-commands", "fail-on",
              "upload-sarif", "review-comments", "github-token"):
        assert i in a["inputs"], i
    assert a["inputs"]["review-comments"]["default"] == "false"       # posting is opt-in
    assert a["runs"]["using"] == "composite"
    text = (ROOT / "action.yml").read_text()
    assert "github/codeql-action/upload-sarif@v3" in text and "docker build" in text
    # every input is forwarded to the container
    run = [s for s in a["runs"]["steps"] if s.get("id") == "run"][0]
    for name in ("PROFILE", "MODE", "BASE_REF", "FAIL_ON", "REVIEW_COMMENTS", "GITHUB_TOKEN", "COMPILE_COMMANDS",
                 "BASELINE"):
        assert f"-e INPUT_{name}" in run["run"] and f"INPUT_{name}" in run["env"]


def test_outputs_declared():
    a = yaml.safe_load((ROOT / "action.yml").read_text())
    assert set(a["outputs"]) == {"sarif-file", "findings", "errors", "partial", "baselined"}


def test_dockerfile_pins_the_measured_toolchain():
    d = (ROOT / "Dockerfile").read_text()
    for pin in ("clang-19=1:19.1.7-3+b1", "clang-tidy-19=1:19.1.7-3+b1", "cppcheck=2.17.1-2"):
        assert pin in d
    acc = json.loads((ROOT / "data/accuracy.json").read_text())
    versions = {t["tool"]: t["version"] for t in acc["tools"]}
    assert versions["clang-tidy"] == "19.1.7" and versions["cppcheck"] == "2.17.1"
    assert "ENTRYPOINT" in d and "cert_review.action" in d


def test_workflows_and_templates_are_valid_yaml():
    for p in (".github/workflows/self-test.yml", "examples/github-workflow.yml",
              "examples/github-workflow-pull-request-target-comment.yml",
              "ci/gitlab/cert-review.gitlab-ci.yml", "ci/github/cert-review.yml",
              "ci/github/pr-cert-review-mcp.yml"):
        assert yaml.safe_load((ROOT / p).read_text()), p
    gl = yaml.safe_load((ROOT / "ci/gitlab/cert-review.gitlab-ci.yml").read_text())
    assert set(gl["cert-review"]["artifacts"]["reports"]) == {"codequality", "sast"}
    st = yaml.safe_load((ROOT / ".github/workflows/self-test.yml").read_text())
    assert "action" in st["jobs"] and "uses: ./" in (ROOT / ".github/workflows/self-test.yml").read_text()


def test_inputs_and_globs(monkeypatch):
    monkeypatch.setenv("INPUT_FAIL_ON", "error")
    assert action.inp("fail-on") == "error" and action.inp("missing", "d") == "d"
    assert action.split_globs("a/**, b\nc") == ["a/**", "b", "c"]
    assert action.truthy("TRUE") and not action.truthy("false")


def _f(path, sev="warning"):
    f = F.make("ERR34-C", path, 3, 1, "clang-tidy", "cert-err34-c", "m", 0.9, P.load("default")).to_dict()
    f["severity"] = sev
    return f


def test_filter_paths():
    fs = [_f("/r/src/a.c"), _f("/r/third_party/b.c")]
    out = action.filter_paths(fs, "/r", ["src/*", "third_party/*"], ["third_party/*"])
    assert [f["file"] for f in out] == ["/r/src/a.c"]


def test_summary_markdown():
    md = action.summary_md({"tools": [{"tool": "clang-tidy", "version": "19", "available": True,
                                       "files_with_errors": ["x"]}], "files": ["a"]},
                           [_f("/r/a.c", "error")], "/r", "diff", "default", True, "error")
    assert "1 error" in md and "Failing" in md and "ERR34-C" in md and "compile errors" in md


def test_codequality_and_sast_formats():
    cq = Fm.to_codequality([_f("/r/a.c", "error")], "/r")[0]
    assert cq["severity"] == "critical" and cq["location"] == {"path": "a.c", "lines": {"begin": 3}}
    assert len(cq["fingerprint"]) == 64
    sast = Fm.to_gitlab_sast([_f("/r/a.c")], "/r")
    v = sast["vulnerabilities"][0]
    assert sast["scan"]["type"] == "sast" and v["severity"] == "Medium"
    assert any(i["type"] == "cert" for i in v["identifiers"]) and any(i["type"] == "cwe" for i in v["identifiers"])
    assert Fm.format_review([_f("/r/a.c")], "codequality", "/r")


def _run(tmp_path, env, monkeypatch):
    out, summ = tmp_path / "out.txt", tmp_path / "summary.md"
    out.write_text(""); summ.write_text("")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summ))
    for k, v in env.items():
        monkeypatch.setenv("INPUT_" + k, v)
    rc = action.main()
    return rc, out.read_text(), summ.read_text()


@need_clang_tidy
def test_entrypoint_full_mode_on_corpus(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text((ROOT / "corpus/ERR34-C/nc1_1.c").read_text())
    rc, out, summ = _run(tmp_path, {"MODE": "full", "PATHS": "src", "FAIL_ON": "warning",
                                     "TOOLS": "clang-tidy", "MIN_CONFIDENCE": "0.5"}, monkeypatch)
    assert rc == 1                                     # fail-on warning, ERR34-C is a warning
    assert "findings=" in out and "ERR34-C" in summ
    sarif = json.loads((tmp_path / "cert-review.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert any(r["ruleId"] == "ERR34-C" for r in sarif["runs"][0]["results"])


@need_clang_tidy
def test_entrypoint_baseline_hides_known_findings(tmp_path, monkeypatch):
    from cert_review import api
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text((ROOT / "corpus/ERR34-C/nc1_1.c").read_text())
    res = api.check_file([str(src)], tools=["clang-tidy"], min_confidence=0.5, root=str(tmp_path))
    assert res["findings"]
    api.write_baseline(res, str(tmp_path / ".cert-review-baseline.json"))
    (src / "a.c").write_text("/* shifted */\n\n" + (ROOT / "corpus/ERR34-C/nc1_1.c").read_text())
    rc, out, summ = _run(tmp_path, {"MODE": "full", "PATHS": "src", "FAIL_ON": "warning", "TOOLS": "clang-tidy",
                                     "MIN_CONFIDENCE": "0.5", "BASELINE": ".cert-review-baseline.json"},
                         monkeypatch)
    assert rc == 0 and "findings=0" in out and f"baselined={len(res['findings'])}" in out
    assert "already baselined" in summ


@need_clang_tidy
def test_entrypoint_diff_mode_only_changed_files(tmp_path, monkeypatch):
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *a],
                       check=True, capture_output=True)
    bad = (ROOT / "corpus/ERR34-C/nc1_1.c").read_text()
    git("init", "-q")
    (tmp_path / "old.c").write_text(bad)
    git("add", "."); git("commit", "-qm", "base")
    (tmp_path / "new.c").write_text(bad)
    git("add", "."); git("commit", "-qm", "change")
    rc, out, summ = _run(tmp_path, {"MODE": "diff", "BASE_REF": "HEAD~1", "TOOLS": "clang-tidy"}, monkeypatch)
    assert rc == 0
    sarif = json.loads((tmp_path / "cert-review.sarif").read_text())
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]}
    assert uris == {"new.c"}


def test_review_comments_are_opt_in_and_need_a_token(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.c").write_text("int main(void){return 0;}\n")
    monkeypatch.setattr(action, "post_review", lambda *a, **k: pytest.fail("must not post"))
    rc, _, _ = _run(tmp_path, {"MODE": "full", "PATHS": "a.c", "TOOLS": "cppcheck"}, monkeypatch)
    assert rc == 0
    rc, _, _ = _run(tmp_path, {"MODE": "full", "PATHS": "a.c", "TOOLS": "cppcheck", "REVIEW_COMMENTS": "true"},
                    monkeypatch)
    assert rc == 0 and "skipped" in capsys.readouterr().out


def test_review_comment_payload_posted_once(tmp_path, monkeypatch):
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps({"pull_request": {"number": 7, "head": {"repo": {"fork": False}}}}))
    sent = []
    monkeypatch.setattr(action, "post_review", lambda payload, repo, pr, token, url: sent.append((payload, repo, pr)))
    monkeypatch.setattr(action.api, "check_file", lambda *a, **k: {
        "findings": [_f(str(tmp_path / "a.c"))], "tools": [], "files": []})
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    rc, _, _ = _run(tmp_path, {"MODE": "full", "REVIEW_COMMENTS": "true", "GITHUB_TOKEN": "t"}, monkeypatch)
    assert rc == 0 and len(sent) == 1 and sent[0][1:] == ("o/r", 7)
    assert sent[0][0]["event"] == "COMMENT" and sent[0][0]["comments"][0]["path"] == "a.c"
