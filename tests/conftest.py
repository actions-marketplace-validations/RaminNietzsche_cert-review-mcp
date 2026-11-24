import shutil
import subprocess
from pathlib import Path

import pytest

need_clang_tidy = pytest.mark.skipif(shutil.which("clang-tidy") is None, reason="clang-tidy not installed")
need_cppcheck = pytest.mark.skipif(shutil.which("cppcheck") is None, reason="cppcheck not installed")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def tiny_git_repo(tmp_path: Path) -> dict[str, str]:
    """Two-commit repo with one C++ file; returns repo path, base and head SHAs."""
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "cert-review@test")
    _git(tmp_path, "config", "user.name", "cert-review")
    src = tmp_path / "sample.cc"
    src.write_text("void f() {}\n")
    _git(tmp_path, "add", "sample.cc")
    _git(tmp_path, "commit", "-m", "base")
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    src.write_text("void f() { if(1) {} }\n")
    _git(tmp_path, "add", "sample.cc")
    _git(tmp_path, "commit", "-m", "change")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    return {"repo": str(tmp_path), "base": base, "head": head}