"""Git helpers. Everything here respects GIT_INDEX_FILE, so it works inside a pre-commit hook."""

from __future__ import annotations

import os
import re
import subprocess


class GitError(RuntimeError):
    pass


_GIT_URL_RE = re.compile(r"^(https?://|ssh://|git://|file://|git@[^:]+:).+", re.IGNORECASE)


def is_git_url(value: str) -> bool:
    return bool(_GIT_URL_RE.match(value.strip()))


def clone_repo(url: str, dest: str, branch: str | None = None) -> None:
    args = ["clone", "--depth", "1"]
    if branch:
        args += ["--branch", branch]
    args += [url.strip(), dest]
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise GitError(f"git clone failed: {proc.stderr.strip()}")


def _git(args: list[str], cwd: str, check: bool = True, text: bool = True) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=text)
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def find_repo_root(path: str = ".") -> str | None:
    try:
        out = _git(["rev-parse", "--show-toplevel"], cwd=path)
    except (GitError, FileNotFoundError, NotADirectoryError):
        return None
    return out.strip() or None


def _split_z(out: str) -> list[str]:
    return [p for p in out.split("\0") if p]


def staged_files(root: str) -> list[str]:
    """Files added/copied/modified/renamed in the index (deleted files have nothing to scan)."""
    return _split_z(_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], cwd=root))


def unstaged_files(root: str) -> list[str]:
    """Files whose working-tree version differs from the index version."""
    return _split_z(_git(["diff", "--name-only", "-z"], cwd=root))


def partially_staged(root: str, staged: list[str] | None = None) -> list[str]:
    staged = staged if staged is not None else staged_files(root)
    dirty = set(unstaged_files(root))
    return [f for f in staged if f in dirty]


def listed_files(root: str) -> list[str]:
    """Tracked files plus untracked, non-ignored files (the working tree as the developer sees it)."""
    files = _split_z(_git(["ls-files", "-co", "--exclude-standard", "-z"], cwd=root))
    return [f for f in files if os.path.isfile(os.path.join(root, f))]


def checkout_index(root: str, files: list[str], dest: str) -> None:
    """Write the *staged* (index) version of files into dest, preserving relative paths."""
    prefix = os.path.join(os.path.abspath(dest), "")
    for i in range(0, len(files), 200):
        _git(["checkout-index", f"--prefix={prefix}", "--", *files[i : i + 200]], cwd=root)


def staged_content(root: str, path: str) -> str | None:
    proc = subprocess.run(["git", "show", f":{path}"], cwd=root, capture_output=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def stage_file(root: str, path: str) -> None:
    _git(["add", "--", path], cwd=root)


def file_diff(root: str, path: str, cached: bool = False) -> str:
    args = ["diff", "--no-color"] + (["--cached"] if cached else []) + ["--", path]
    return _git(args, cwd=root, check=False)


def user_identity(root: str | None) -> str:
    if not root:
        return os.environ.get("USER", "unknown")
    email = _git(["config", "user.email"], cwd=root, check=False).strip()
    return email or os.environ.get("USER", "unknown")


def hooks_dir(root: str) -> str:
    out = _git(["rev-parse", "--git-path", "hooks"], cwd=root).strip()
    return out if os.path.isabs(out) else os.path.join(root, out)

