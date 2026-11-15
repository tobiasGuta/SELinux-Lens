"""Main entrypoint; keeps CLI help and tests usable without GTK installed."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="selinux-lens",
        description="Read-only Fedora SELinux denial explorer.",
    )
    parser.add_argument("--demo", action="store_true", help="Show fictional demo records.")
    parser.add_argument("--version", action="version", version=f"SELinux Lens {__version__}")
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        print("Launch SELinux Lens from your regular desktop account.", file=sys.stderr)
        return 2
    try:
        from .gui import launch
    except (ImportError, ValueError) as exc:
        print(
            "SELinux Lens requires Fedora's GTK4, Libadwaita and PyGObject packages. "
            f"Details: {exc}",
            file=sys.stderr,
        )
        return 2
    return launch(demo=args.demo)


if __name__ == "__main__":
    raise SystemExit(main())
