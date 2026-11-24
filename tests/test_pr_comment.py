from cert_review import pr_comment as PC
from cert_review.api import format_pr_review


def test_style_nits_detects_if_spacing():
    code = "  if(!from_remote_zone) {\n    return 0;\n  }\n"
    nits = PC.style_nits_in_text(code, "group.cc")
    msgs = {n["message"] for n in nits}
    assert any("if (`" in m for m in msgs)


def test_format_pr_review_includes_sections():
    check = {
        "findings": [],
        "warnings": ["clang-tidy partial"],
        "tools": [{"tool": "clangsa", "status": "ok", "available": True}],
    }
    packet = {
        "hunks": [{
            "file": "src/rgw/driver/rados/group.cc",
            "start_line": 215,
            "end_line": 227,
            "code": "if(!from_remote_zone) {\n  ldpp_dout(dpp, 1) << x;\n}\n",
            "candidate_rules": [{"rule_id": "ERR57-CPP", "title": "Do not leak resources"}],
            "idioms": [{"id": "errno_returns", "hint": "propagate r"}],
        }],
    }
    out = format_pr_review(
        title="rgw/group: test",
        scope="`abc`..`def` — group.cc",
        check_result=check,
        packet=packet,
    )
    md = out["markdown"]
    assert "Heuristic hints" in md
    assert "Style nits" in md
    assert "ERR57-CPP" in md
    assert "errno_returns" in md
    assert "from_remote_zone" in md


def test_format_pr_review_github_footer():
    out = format_pr_review(
        check_result={"findings": [], "warnings": [], "tools": []},
        packet={"hunks": []},
        github_footer="pull_request_target",
    )
    md = out["markdown"]
    assert "cert-review-mcp · auto-generated" in md
    assert "pull_request_target" in md
    assert "<!-- cert-review -->" in md