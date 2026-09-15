# secret-gate

A pre-commit secret gate that inspects the object git is actually about to
commit — the **staged blob** — instead of the file on disk.

## Why this exists

The standard pre-commit hook does this:

```bash
staged=$(git diff --cached --name-only --diff-filter=ACM)
python3 scan_secrets.py $staged
```

That checks the wrong bytes. `git commit` writes the **index blob**, which is
not the working-tree file. The realistic accident:

```bash
git add config.env        # contains DB_PASSWORD=RealSecret123
vim config.env            # "clean it up" -> DB_PASSWORD=placeholder
git commit                # hook reads disk (clean) -> exit 0
                          # git commits the STAGED blob (secret) -> leaked
```

Reproduced against this SOP's own hook. Exit code 0, and the secret landed in
history. It is the same failure class as the `.env.bak` leak that motivated the
scanner in the first place: **the gate inspected a different object than the one
being committed.**

## What it does

| Mode | Object inspected | Catches |
|------|------------------|---------|
| default | every entry in the index (`git cat-file blob :path`) | the staged-blob-vs-disk divergence |
| `--history` | every blob reachable from all refs | a secret committed and later deleted |

Plus a warning path: if the **staged** version is clean but the **working copy**
is dirty *and* contains a secret, it warns. The commit is safe, but the
developer clearly believes otherwise — better to remove it now than to commit it
next time.

## Usage

```bash
# as a pre-commit hook (the default mode)
python3 src/secret_gate.py

# audit an existing repo before publishing
python3 src/secret_gate.py --history

# explicit paths
python3 src/secret_gate.py --repo /path/to/repo --scanner /path/to/scan_secrets.py -v
```

Exit codes: `0` clean · `1` secret found (block) · `2` gate could not run.

**Exit 2 is fail-closed on purpose.** A gate that shrugs when its scanner is
missing is advertising protection it does not provide.

## The pattern engine is not duplicated

`secret_gate.py` delegates detection to `scan_secrets.py` and only changes
*which bytes* are read. One pattern engine means one place to fix a false
positive, and the engine keeps its own 39-case regression battery.

## Tests

```bash
python3 tests/test_secret_gate.py
```

12 cases. Every one was verified to fail when the fix is reverted:

| Suite | What it pins |
|-------|--------------|
| `TestStagedBlobIsWhatGetsScanned` | the bug itself, plus the mirror case (clean staged / dirty disk must **not** block — over-blocking trains people to bypass the hook) |
| `TestFrameworkCodeStillPasses` | normal framework code commits cleanly (Laravel facades, `.htaccess` XSRF, `env()` references) |
| `TestHistoryMode` | a secret committed then deleted is still found |
| `TestRobustness` | binary blobs, nested paths, deletions, empty index |

Reverting the fix (scanning disk instead of the index) turns **2 of 12 red**.

## Limits — stated, not hidden

- The engine is regex-based. A secret in an unusual format can still slip
  through; this is a safety net, not a guarantee.
- `--history` scans blob *content*. It does not detect a secret leaked in a
  commit message, a branch name, or a tag name.
- Rewriting history does **not** un-leak a credential that was already pushed
  or cloned. **Rotate first.** This tool finds the leak; it cannot undo it.
