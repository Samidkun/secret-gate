#!/usr/bin/env python3
"""Regression battery for secret_gate.py.

Run: python3 tests/test_secret_gate.py    (exit 0 = all good)

WHY THIS EXISTS

A pre-commit hook that scans the files on disk is checking the wrong object.
Git commits the STAGED BLOB, which can differ from the working-tree file. The
realistic accident:

    git add config.env        # still contains DB_PASSWORD=RealSecret
    vim config.env            # "clean it up" -> DB_PASSWORD=placeholder
    git commit                # hook reads disk (clean), git commits the secret

The hook reported success and the secret landed in history. This was
reproduced against the SOP's own pre-commit hook; it is the same failure class
as the .env.bak leak that motivated the scanner in the first place: the gate
inspected a different object than the one being committed.

So every test below is about WHICH BYTES get scanned, not which patterns are
used. The pattern engine is reused from scan_secrets.py - it was already
proven by its own 39-case battery.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
GATE = os.path.join(PROJECT, "src", "secret_gate.py")
SCANNER = os.environ.get(
    "SECRET_GATE_SCANNER",
    os.path.expanduser(
        "~/.hermes/skills/software-development/project-bootstrap/scripts/scan_secrets.py"
    ),
)

SECRET = "DB_PASSWORD=RealSecret123"
CLEAN = "DB_PASSWORD=placeholder"


class GitRepoCase(unittest.TestCase):
    """Base: a throwaway git repo per test, with a helper to run the gate."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="secret-gate-test-")
        self.git("init", "-q")
        self.git("config", "user.email", "t@t")
        self.git("config", "user.name", "t")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.dir, capture_output=True, text=True
        )

    def write(self, name, content):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def run_gate(self, *args):
        proc = subprocess.run(
            [sys.executable, GATE, "--scanner", SCANNER, *args],
            cwd=self.dir,
            capture_output=True,
            text=True,
        )
        return proc

    def assertBlocked(self, proc, why):
        self.assertNotEqual(
            proc.returncode,
            0,
            f"gate must BLOCK ({why})\nstdout: {proc.stdout}\nstderr: {proc.stderr}",
        )

    def assertAllowed(self, proc, why):
        self.assertEqual(
            proc.returncode,
            0,
            f"gate must ALLOW ({why})\nstdout: {proc.stdout}\nstderr: {proc.stderr}",
        )


class TestStagedBlobIsWhatGetsScanned(GitRepoCase):
    """The whole point: scan the staged blob, not the working-tree file."""

    def test_blocks_when_the_secret_is_only_in_the_staged_blob(self):
        """THE BUG. Stage a secret, then clean the file on disk.

        A disk-scanning hook reads CLEAN and lets it through, while git commits
        the secret. This must block.
        """
        self.write("config.env", SECRET + "\n")
        self.git("add", "config.env")

        # the user "cleans it up" after staging - disk is now clean
        self.write("config.env", CLEAN + "\n")
        with open(os.path.join(self.dir, "config.env")) as fh:
            self.assertNotIn("RealSecret", fh.read(), "precondition: disk must be clean")

        proc = self.run_gate()
        self.assertBlocked(proc, "the staged blob still holds the secret")
        self.assertIn("config.env", proc.stdout + proc.stderr)

    def test_allows_when_the_secret_is_only_on_disk(self):
        """The mirror case: staged is clean, disk is dirty.

        git will commit the clean blob, so the gate must not block. Blocking
        here would train the developer to bypass the hook.
        """
        self.write("config.env", CLEAN + "\n")
        self.git("add", "config.env")
        self.write("config.env", SECRET + "\n")  # unstaged edit only

        proc = self.run_gate()
        self.assertAllowed(proc, "git commits the clean staged blob, not the disk file")

    def test_blocks_a_normal_staged_secret(self):
        """Sanity: the ordinary path still blocks."""
        self.write("config.env", SECRET + "\n")
        self.git("add", "config.env")

        proc = self.run_gate()
        self.assertBlocked(proc, "a plainly staged secret must never pass")

    def test_allows_a_clean_commit(self):
        self.write("README.md", "# project\n")
        self.git("add", "README.md")

        proc = self.run_gate()
        self.assertAllowed(proc, "nothing sensitive staged")

    def test_only_staged_files_are_considered(self):
        """An untracked secret file must not block an unrelated commit."""
        self.write("notes.md", "# notes\n")
        self.git("add", "notes.md")
        self.write("local.env", SECRET + "\n")  # never added

        proc = self.run_gate()
        self.assertAllowed(proc, "untracked files are not being committed")

    def test_deleting_a_file_does_not_crash_the_gate(self):
        self.write("gone.env", SECRET + "\n")
        self.git("add", "gone.env")
        self.git("commit", "-qm", "add")
        self.git("rm", "-q", "gone.env")

        proc = self.run_gate()
        self.assertAllowed(proc, "a deletion has no blob content to scan")


class TestFrameworkCodeStillPasses(GitRepoCase):
    """The scanner's MUST_PASS list, driven through the gate end to end."""

    FRAMEWORK_SNIPPETS = [
        ("php facade", 'password => [Rules\\Password::defaults()]'),
        ("hash make", '"password" => Hash::make($request->password),'),
        ("empty env example", "DB_PASSWORD=\nMAIL_PASSWORD="),
        ("placeholder", "API_KEY=your_key_here"),
        ("env reference", "API_KEY=${MY_KEY}"),
        ("htaccess xsrf", "RewriteRule .* - [E=HTTP_X_XSRF_TOKEN:%{HTTP:X-XSRF-Token}]"),
        ("config env()", "'password' => env('DB_PASSWORD', ''),"),
    ]

    def test_normal_framework_code_commits_cleanly(self):
        for name, snippet in self.FRAMEWORK_SNIPPETS:
            with self.subTest(snippet=name):
                path = self.write(f"f_{name.replace(' ', '_')}.txt", snippet + "\n")
                self.git("add", path)
                proc = self.run_gate()
                self.assertAllowed(proc, f"framework snippet: {name}")
                self.git("reset", "-q", path)


class TestHistoryMode(GitRepoCase):
    """A secret already committed is still a leak - catch it, do not ignore it."""

    def test_history_mode_finds_a_secret_that_was_later_deleted(self):
        """The .env.bak class: committed, then removed. Pre-commit cannot see it.

        The working tree and the index are both clean, so the normal gate
        passes. --history must still find it, because the blob is permanent
        until the credential is rotated and history is rewritten.
        """
        self.write(".env.bak", SECRET + "\n")
        self.git("add", ".env.bak")
        self.git("commit", "-qm", "oops")
        self.git("rm", "-q", ".env.bak")
        self.git("commit", "-qm", "remove it")

        # normal gate: nothing staged, nothing to see
        self.assertAllowed(self.run_gate(), "nothing is staged any more")

        # history mode: the blob is still there
        proc = self.run_gate("--history")
        self.assertBlocked(proc, "the secret is still in history")

    def test_history_mode_allows_a_clean_repo(self):
        self.write("README.md", "# clean\n")
        self.git("add", "README.md")
        self.git("commit", "-qm", "init")

        proc = self.run_gate("--history")
        self.assertAllowed(proc, "no secret ever committed")


class TestRobustness(GitRepoCase):
    def test_binary_files_do_not_crash_the_gate(self):
        path = os.path.join(self.dir, "logo.png")
        with open(path, "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256)))
        self.git("add", "logo.png")

        proc = self.run_gate()
        self.assertAllowed(proc, "binary content is not a secret and must not crash")

    def test_reports_the_offending_path_and_line(self):
        self.write("deep/nested/.env.prod", "line1\n" + SECRET + "\n")
        self.git("add", "deep/nested/.env.prod")

        proc = self.run_gate()
        self.assertBlocked(proc, "nested secret must be found")
        out = proc.stdout + proc.stderr
        self.assertIn(".env.prod", out, "must name the file")
        self.assertIn(":2", out, "must name the line number")

    def test_scan_runs_when_nothing_is_staged(self):
        proc = self.run_gate()
        self.assertAllowed(proc, "an empty index is not an error")


if __name__ == "__main__":
    if not os.path.isfile(GATE):
        print(f"FAIL: gate not implemented yet: {GATE}")
        sys.exit(1)
    if not os.path.isfile(SCANNER):
        print(f"FAIL: pattern engine not found: {SCANNER}")
        sys.exit(1)
    unittest.main(verbosity=2)
