"""Allow ``python -m ghidriff_mcp`` to run the server."""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
