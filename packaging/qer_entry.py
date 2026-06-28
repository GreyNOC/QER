"""PyInstaller entry point for the standalone, portable ``qer.exe``.

PyInstaller bundles a script (not a ``-m`` module), so this thin launcher calls
the real CLI. Build with ``packaging/build-exe.ps1`` (or the command in it).
"""

import sys

from qer.cli import main

if __name__ == "__main__":
    sys.exit(main())
