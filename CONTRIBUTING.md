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

## Before you open a pull request

Both must pass; CI runs them on Windows with Python 3.10 and 3.13:

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

The internals -- pipeline stages, module layout, how detections and the
lateral-movement graph are built -- are in [ARCHITECTURE.md](docs/ARCHITECTURE.md).
