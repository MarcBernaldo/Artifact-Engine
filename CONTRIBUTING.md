# Contributing

Thank you for helping. Artifact-Engine is source-available under the
[PolyForm Noncommercial 1.0.0](LICENSE) license; by contributing you agree that
your contribution is licensed under the same terms.

For anything beyond a small fix, open an issue first and say what you want to
change: it saves work on both sides. Security problems go through the
[security policy](SECURITY.md), never a public issue.

## Case data never becomes text

This tool processes real evidence. Nothing taken from a case -- hostnames,
usernames, IP addresses, domains, file paths, account, organisation or case names
-- may appear in code, comments, tests, fixtures, documentation, commit messages,
branch names, issues or pull requests. Use invented placeholders (`HOST-01`,
`jdoe`, `10.0.0.5`, `example.local`). To explain a bug, describe the *shape* of
a value, not the value.

## Setting up

The engine runs on Windows, with Python 3.10 or later.

```sh
git clone https://github.com/MarcBernaldo/Artifact-Engine.git
cd Artifact-Engine
pip install -e ".[dev]"
```

## Developing and testing locally

The install is editable, so an edit under `src/` is live: `aeng` and the tests run
the code you just saved. The loop, in order:

1. **Branch.** Work on `dev/<topic>`, never on `main`.
2. **Change one thing and test it.** Write the test with the change, run only that
   file while you work (`python -m pytest -q tests/test_<area>.py`), and check that
   the test fails with the change undone.
3. **Run what CI runs, before the push:**

   ```sh
   python scripts/check.py
   ```

   It runs ruff, the whole suite on your Python and the whole suite on Python
   3.10, and ends with `READY` or `NOT READY` and the step that failed. The 3.10
   leg needs [uv](https://docs.astral.sh/uv/) on PATH; it is built once in
   `.venv310/` and reused. `--fast` leaves it out while you iterate, and says so
   in its last line.

   | Step | What it runs | Roughly |
   |---|---|---|
   | version | the same version in `pyproject.toml` and `__init__.py` | instant |
   | lint | `python -m ruff check src/ tests/` | seconds |
   | tests | `python -m pytest -q` on this Python | 2-3 min |
   | tests on 3.10 | the same suite in `.venv310/` | 2-3 min |
   | real cases | only with `--real`, see below | minutes per case |

4. **Run it on evidence** when the change alters what is parsed, the names of
   tables or the consolidated outputs. The suite is synthetic and cannot say what
   a real acquisition does:

   ```sh
   python scripts/check.py --real C:\Cases
   ```

   That runs `aeng run` over every case folder under the given root (or under the
   `AENG_CASES` variable), one after another, and prints figures only, from each
   case's `run-summary.json`: status, machines, parsers ok, skipped and errors.
   A parser error fails the step. A case that ends `incomplete` with no parser
   error is reported and does not: an acquisition known to be truncated ends that
   way on every run. `--only a,b` and `--skip c` pick the folders. To try one
   change on one case by hand, `aeng run -p <case>` re-runs only the parsers whose
   code changed, and `aeng lateral -p <case>` rebuilds only the graph.

## Before you open a pull request

`python scripts/check.py` must end `READY`. It is these two, which CI runs on
Windows with Python 3.10 and 3.13:

```sh
python -m pytest -q
python -m ruff check src/ tests/
```

- **Tests prove the change.** A test for a fix must fail with the fix reverted;
  one that passes either way proves nothing. Test data is synthetic.
- **Docs stay true.** If the change makes a statement in `README.md` or
  `docs/` false, fix it in the same pull request.
- **Parser manifests regenerate the map.** After adding or editing a file in
  `src/artifact_engine/data/parsers/`, run `python -m artifact_engine.core.atlas`
  and commit the new `docs/atlas.html`; a test fails until you do. Adding a
  parser is described in [How to add a parsing tool](README.md#how-to-add-a-parsing-tool).
- **One logical change per commit**, staged by explicit path: generated files and
  case outputs must not slip in.
- **Do not change the version.** Releases are cut by the maintainer.

## Releasing (maintainer)

One version per development, released when every function in it is complete and
tested.

1. On `dev/<topic>`: one commit per function, no version change.
2. `python scripts/check.py --real <cases root>` ends `READY`.
3. The last commit of the branch adds the entry to `CHANGELOG.md` and bumps the
   version in `pyproject.toml` and `src/artifact_engine/__init__.py`.
4. `main` fast-forwards to the branch, and only `main` is pushed.
5. CI runs on the push. A defect found after it goes into the next version:
   published history is never rewritten.

The internals -- pipeline stages, module layout, how detections and the
lateral-movement graph are built -- are in [ARCHITECTURE.md](docs/ARCHITECTURE.md).
