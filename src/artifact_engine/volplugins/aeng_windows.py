"""`windows.vadyarascan` whose matches never stop the scan (v0.7.164).

Volatility renders a match's bytes (its `Value` column, a `LayerData`) only when
the table is written, and its renderer passes the END of the match where
`layer.mapping` takes a LENGTH. On some matches that far larger range comes back
with no mapping at all, though the match's own range has one, and the
renderer's first `next()` raises StopIteration -- which ends the whole plugin,
every row already found lost with it. Seen on a Windows 10 image: exit 1 at row
1,243 of 3,507, and 1,529 of the 3,507 hitting it.

Here the bytes are rendered as the plugin yields them, by Volatility's own
renderer, so the text is the same; only when it raises are the bytes missing
from the image (shown `__`) found from the match's own range instead. The
column is the rendered text, which is what the CSV held.

Run as `aeng_windows.VadYaraScan` with this folder on `-p`.
"""

from __future__ import annotations

from volatility3.cli import text_renderer
from volatility3.framework import renderers
from volatility3.plugins.windows import vadyarascan


class _Dump(text_renderer.LayerDataRenderer):
    """Volatility's LayerData rendering, its empty-mapping StopIteration caught."""

    def render_bytes(self, data):
        try:
            return super().render_bytes(data)
        except StopIteration:
            layer = data.context.layers[data.layer_name]
            mapped = [(start, size) for start, size, *_ in
                      layer.mapping(data.offset, data.length, True)]
            missing = {i for i in range(data.length)
                       if not any(start <= data.offset + i < start + size
                                  for start, size in mapped)}
            return layer.read(data.offset, data.length, True), missing


class VadYaraScan(vadyarascan.VadYaraScan):
    """YARA over every process's VADs, each match's bytes rendered as it is found."""

    def _generator(self):
        dump = _Dump()
        for level, row in super()._generator():
            yield level, (*row[:-1], dump(row[-1]))

    def run(self):
        grid = super().run()
        columns = [(c.name, str if c.type is renderers.LayerData else c.type)
                   for c in grid.columns]
        return renderers.TreeGrid(columns, self._generator())
