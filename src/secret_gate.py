#!/usr/bin/env python3
"""secret_gate - a pre-commit secret gate that inspects the right object.

THE PROBLEM THIS SOLVES

The usual pre-commit hook scans the files on disk:

    staged=$(git diff --cached --name-only --diff-filter=ACM)
    python3 scan_secrets.py $staged

That checks the WRONG BYTES. Git commits the staged blob, which is not the
working-tree file. The realistic accident:

    git add config.env        # contains DB_PASSWORD=RealSecret
    vim config.env            # "clean it up" -> DB_PASSWORD=placeholder
    git commit                # hook reads disk (clean), git commits the secret

Reproduced against the SOP's own hook: exit 0, and the secret landed in
history. Same failure class as the .env.bak leak that motivated the scanner -
the gate inspected a different object than the one being committed.

WHAT THIS DOES INSTEAD

  1. Read each staged entry from the INDEX (`git cat-file blob :path`), not
     from the working tree. That is byte-for-byte what `git commit` writes.
  2. Also detect the reverse accident: a file whose STAGED version is clean but
     whose WORKING copy is dirty, where the disk version carries a secret. The
     commit is safe, but the developer clearly believes otherwise; warn so the
     secret is removed rather than lingering to be committed next time.
  3. `--history` walks every blob reachable from all refs. A secret that is
     already committed is permanent until the credential is rotated, and the
     ordinary gate cannot see it because the file is no longer staged.

EXIT CODES

  0  nothing sensitive found
  1  a secret was found in the staged blob (commit must not proceed)
  2  the gate could not run (no scanner, not a repo) - FAIL CLOSED

Usage:
    python3 secret_gate.py [--history] [--scanner PATH] [--repo DIR] [-v]

The pattern engine is reused verbatim from scan_secrets.py. It already has its
own 39-case regression battery; this tool only changes WHICH BYTES it reads.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCANNER = os.path.join(
    os.path.expanduser("~"),
    ".hermes",
    "skills",
    "software-development",
    "project-bootstrap",
    "scripts",
    "scan_secrets.py",
)

# Extensions that cannot contain a text secret and may be huge. The scanner
# itself tolerates binary data, but skipping keeps history mode fast.
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svgz",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".webm", ".ogg", ".wav",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".class", ".jar",
    ".sqlite", ".db", ".pyc", ".lockb",
}

# Files with no content worth scanning (and where a "secret" is meaningless).
SKIP_NAMES = {".gitkeep", ".DS_Store"}


def git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
        errors="replace",
    )


def is_repo(repo: str) -> bool:
    return git(repo, "rev-parse", "--git-dir").returncode == 0


def scan_bytes(scanner: str, data: bytes, label: str, tmpdir: str) -> list[str]:
    """Run the pattern engine over a byte blob. Returns its report lines."""
    if not data:
        return []
    # The engine reads a file path, so materialise the exact bytes. A binary
    # blob is written as-is; the engine tolerates undecodable input.
    path = os.path.join(tmpdir, "blob")
    with open(path, "wb") as fh:
        fh.write(data)

    proc = subprocess.run(
        [sys.executable, scanner, path],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode == 0:
        return []

    lines = []
    for line in (proc.stderr or "").splitlines():
        line = line.strip()
        if not line or line.startswith("BLOCKED:"):
            continue
        # rewrite the temp path back to something the developer recognises
        lines.append(line.replace(path, label, 1))
    return lines or [f"{label}: scanner flagged this blob"]


def staged_entries(repo: str) -> list[tuple[str, str, str]]:
    """(mode, sha, path) for every entry in the index.

    Reads the index directly, so a deleted entry simply has no blob and a
    submodule appears as a commit object (mode 160000) with no file content.
    """
    out = git(repo, "ls-files", "--stage", "-z").stdout
    entries = []
    for chunk in out.split("\0"):
        if not chunk:
            continue
        # "<mode> <sha> <stage>\t<path>"
        meta, _, path = chunk.partition("\t")
        parts = meta.split()
        if len(parts) < 3:
            continue
        mode, sha, stage = parts[0], parts[1], parts[2]
        if stage != "0":  # unmerged; not a single blob to inspect
            continue
        entries.append((mode, sha, path))
    return entries


def blob_bytes(repo: str, sha: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", repo, "cat-file", "blob", sha],
        capture_output=True,
    )
    return proc.stdout if proc.returncode == 0 else b""


def working_bytes(repo: str, path: str) -> bytes:
    full = os.path.join(repo, path)
    if not os.path.isfile(full):
        return b""
    with open(full, "rb") as fh:
        return fh.read()


def history_blobs(repo: str):
    """Yield (sha, hint_path) for every blob reachable from any ref."""
    out = git(repo, "rev-list", "--objects", "--all").stdout
    for line in out.splitlines():
        sha, _, path = line.partition(" ")
        if sha:
            yield sha, path or "<unknown path>"


def should_skip(path: str) -> bool:
    name = os.path.basename(path)
    if name in SKIP_NAMES:
        return True
    _, ext = os.path.splitext(name)
    return ext.lower() in BINARY_EXT


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="secret_gate",
        description="Block commits whose STAGED blob contains a secret.",
    )
    ap.add_argument("--history", action="store_true",
                    help="scan every blob reachable from all refs, not just the index")
    ap.add_argument("--scanner", default=os.environ.get("SECRET_GATE_SCANNER", DEFAULT_SCANNER),
                    help="path to the pattern engine (scan_secrets.py)")
    ap.add_argument("--repo", default=os.getcwd(), help="repository directory")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    repo = os.path.abspath(args.repo)

    if not is_repo(repo):
        print(f"secret_gate: not a git repository: {repo}", file=sys.stderr)
        return 2
    if not os.path.isfile(args.scanner):
        # FAIL CLOSED. A gate that shrugs when its scanner is missing is
        # advertising protection it does not provide.
        print(f"secret_gate: scanner not found: {args.scanner}", file=sys.stderr)
        return 2

    findings: list[str] = []
    warnings: list[str] = []

    with tempfile.TemporaryDirectory(prefix="secret-gate-") as tmpdir:
        if args.history:
            scanned = 0
            for sha, hint in history_blobs(repo):
                if should_skip(hint):
                    continue
                data = blob_bytes(repo, sha)
                if not data:
                    continue
                scanned += 1
                findings.extend(scan_bytes(args.scanner, data, hint, tmpdir))
            if args.verbose:
                print(f"secret_gate: scanned {scanned} blob(s) in history", file=sys.stderr)
        else:
            entries = staged_entries(repo)
            if args.verbose:
                print(f"secret_gate: {len(entries)} staged entr(ies)", file=sys.stderr)

            for mode, sha, path in entries:
                if mode == "160000":  # submodule pointer, no file content
                    continue
                if should_skip(path):
                    continue

                staged = blob_bytes(repo, sha)
                findings.extend(scan_bytes(args.scanner, staged, path, tmpdir))

                # Reverse accident: the commit is safe, but the working copy
                # still holds a secret and the developer probably thinks it is
                # about to be committed. Tell them, do not block.
                work = working_bytes(repo, path)
                if work and work != staged:
                    hits = scan_bytes(args.scanner, work, path, tmpdir)
                    if hits:
                        warnings.append(
                            f"{path}: working copy still contains a secret "
                            f"({len(hits)} hit(s)) - it is NOT being committed, "
                            f"but remove it before it is"
                        )

    if warnings:
        for w in warnings:
            print(f"  warn: {w}", file=sys.stderr)

    if findings:
        print("", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        scope = "history" if args.history else "staged content"
        print(
            f"\nBLOCKED: {len(findings)} possible secret(s) in {scope}.\n"
            f"  If this is a false positive, add an allowlist entry to .gitleaks.toml\n"
            f"  or use a placeholder. If it is real, DO NOT just delete the file -\n"
            f"  rotate the credential, then rewrite history (see the runbook).",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
