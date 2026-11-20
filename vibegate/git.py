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
    out = _git(["rev-parse", "--git-dir"], cwd=root).strip()
    git_dir = out if os.path.isabs(out) else os.path.join(root, out)
    return os.path.join(git_dir, "hooks")


ZERO_SHA = "0" * 40


def push_changed_files(root: str, local_sha: str, remote_sha: str) -> list[str]:
    """Return files added/modified in the commit range being pushed."""
    if not local_sha or local_sha == ZERO_SHA:
        return []
    if not remote_sha or remote_sha == ZERO_SHA:
        # New branch: diff against merge-base with origin/HEAD or list all files at local_sha
        for base_ref in ("origin/main", "origin/master", "main", "master"):
            mb = _git(["merge-base", base_ref, local_sha], cwd=root, check=False).strip()
            if mb and mb != local_sha:
                return _split_z(_git(["diff", "--name-only", "--diff-filter=ACMR", "-z", mb, local_sha], cwd=root))
        return _split_z(_git(["ls-tree", "-r", "--name-only", "-z", local_sha], cwd=root))
    return _split_z(_git(["diff", "--name-only", "--diff-filter=ACMR", "-z", remote_sha, local_sha], cwd=root))


def checkout_commit(root: str, commit_sha: str, files: list[str], dest: str) -> None:
    """Write the exact committed version of files at commit_sha into dest."""
    for rel in files:
        proc = subprocess.run(["git", "show", f"{commit_sha}:{rel}"], cwd=root, capture_output=True)
        if proc.returncode != 0:
            continue
        out_path = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(proc.stdout)


def list_remote_branches_and_prs(repo_dir: str, max_branches: int = 10, max_prs: int = 10) -> list[tuple[str, str]]:
    """Return [(label, sha), ...] for branches and pull/merge requests on origin (newest PRs first)."""
    out = _git(["ls-remote", "origin"], cwd=repo_dir, check=False)
    branches: list[tuple[str, str]] = []
    prs: list[tuple[int, str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        sha, ref = parts[0], parts[1]
        if ref.startswith("refs/heads/"):
            name = ref[len("refs/heads/") :]
            if len(branches) < max_branches:
                branches.append((f"branch:{name}", sha))
        elif ref.startswith("refs/pull/") and ref.endswith("/head"):
            try:
                num = int(ref.split("/")[2])
            except ValueError:
                continue
            prs.append((num, f"PR #{num}", sha))
        elif ref.startswith("refs/merge-requests/") and ref.endswith("/head"):
            try:
                num = int(ref.split("/")[2])
            except ValueError:
                continue
            prs.append((num, f"MR !{num}", sha))
    prs.sort(key=lambda item: item[0], reverse=True)
    return branches + [(label, sha) for _, label, sha in prs[:max_prs]]


def fetch_commit(repo_dir: str, sha: str) -> bool:
    proc = subprocess.run(["git", "fetch", "--depth", "1", "origin", sha], cwd=repo_dir, capture_output=True, text=True)
    return proc.returncode == 0


def changed_files_for_ref(repo_dir: str, base_sha: str, target_sha: str) -> list[str]:
    """Return only files added/modified in target_sha vs base_sha (or in target_sha's commit if shallow)."""
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", "-z", base_sha, target_sha],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return _split_z(proc.stdout)
    # Fallback for shallow clones where base_sha and target_sha have no common ancestor
    proc2 = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "--diff-filter=ACMR", "-r", "-z", target_sha],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    return _split_z(proc2.stdout) if proc2.returncode == 0 else []

