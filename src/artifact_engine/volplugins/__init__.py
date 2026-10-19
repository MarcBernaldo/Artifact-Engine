"""Volatility 3 plugins of the engine's own, loaded by Volatility from this folder
(`-p`), never imported by the engine: each module here imports Volatility, which
the engine does not need to start. Volatility skips files whose name starts with
`__`, so this one is not a plugin."""
