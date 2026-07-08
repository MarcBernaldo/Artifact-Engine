"""Python handlers: escape hatch for parsers with their own logic.

Each handler exposes `run(ctx)` and is referenced from a YAML with
`handler: "artifact_engine.handlers.<module>:run"`.
"""
