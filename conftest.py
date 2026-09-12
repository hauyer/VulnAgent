"""Test-run compatibility shim for OneDrive-synced Windows workspaces.

On some OneDrive/Windows combinations, ``os.mkdir(path, 0o700)`` (the mode
that :func:`tempfile.mkdtemp` hardcodes) creates a directory that the creating
process cannot subsequently list or remove, failing every ``tmp_path`` test
with ``PermissionError: [WinError 5]``. Remapping that one mode to the default
``0o777`` keeps temporary directories listable without changing any test
semantics on normal filesystems. Scoped to Windows so Linux/CI behavior is
unchanged.
"""

from __future__ import annotations

import os

if os.name == "nt":
    _ORIGINAL_MKDIR = os.mkdir

    def _listable_mkdir(path, mode=0o777, *args, **kwargs):
        if mode == 0o700:
            mode = 0o777
        return _ORIGINAL_MKDIR(path, mode, *args, **kwargs)

    os.mkdir = _listable_mkdir
