"""github_footer on PR comment markdown, CLI, API, and fork workflow YAML."""
import subprocess
from pathlib import Path

import pytest
import yaml

from cert_review import cli, pr_comment as PC
from cert_review.api import format_pr_review, review_pr

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATHS = (
    "examples/github-workflow-pull-request-target-comment.yml",
    "ci/github/pr-cert-review-mcp.yml",
)


@pytest.mark.parametrize("via,label", [
    ("pull_request_target", "pull_request_target"),
    ("mcp", "MCP"),
    ("github-action", "GitHub Action"),
])
def test_github_footer_markdown_labels(via, label):
    md = PC.github_footer_markdown(via=via)
    assert "<details>" in md and "cert-review-mcp" in md
    assert label in md


def test_format_pr_review_github_footer_bool():
    out = format_pr_review(
        check_result={"findings": [], "warnings": [], "tools": []},
        packet={"hunks": []},
        github_footer=True,
    )
    assert "pull_request_target" in out["markdown"]


def test_review_pr_api_github_footer(tiny_git_repo):
    res = review_pr(
        tiny_git_repo["repo"],
        tiny_git_repo["base"],
        tiny_git_repo["head"],
        profile="default",
        github_footer="mcp",
        tools=["cppcheck"],
    )
    assert "<!-- cert-review -->" in res["markdown"]
    assert "cert-review-mcp · auto-generated" in res["markdown"]
    assert "`MCP`" in res["markdown"]


def test_cli_review_pr_github_footer(tiny_git_repo, tmp_path):
    out = tmp_path / "comment.md"
    rc = cli.main([
        "review-pr",
        "--repo", tiny_git_repo["repo"],
        "--base", tiny_git_repo["base"],
        "--head", tiny_git_repo["head"],
        "--profile", "default",
        "--tools", "cppcheck",
        "--github-footer", "github-action",
        "--fail-on", "never",
        "-o", str(out),
    ])
    assert rc == 0
    body = out.read_text()
    assert "github-action" in body.lower() or "GitHub Action" in body


def test_fork_workflow_example_matches_ci_copy():
    a = (ROOT / WORKFLOW_PATHS[0]).read_text()
    b = (ROOT / WORKFLOW_PATHS[1]).read_text()
  # ci copy omits top comment lines only
    assert "--entrypoint cert-review" in a and a.split("run_review")[1] == b.split("run_review")[1]


@pytest.mark.parametrize("rel", WORKFLOW_PATHS)
def test_fork_workflow_yaml_structure(rel):
    text = (ROOT / rel).read_text()
    doc = yaml.safe_load(text)
    assert doc and "jobs" in doc
    job = doc["jobs"]["pr-cert-review-mcp"]
    on = doc.get("on") or doc.get(True)  # YAML 1.1: bare `on:` parses as True
    assert on and "pull_request_target" in on
    assert "--entrypoint cert-review" in text
    assert "peter-evans/find-comment" in text
    assert "review-pr" in text
    assert job["timeout-minutes"] >= 30


def test_server_json_version_matches_package():
    import cert_review
    import json

    sj = json.loads((ROOT / "server.json").read_text())
    assert sj["version"] == cert_review.__version__
    assert cert_review.__version__ in sj["packages"][0]["identifier"]