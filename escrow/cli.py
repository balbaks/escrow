"""Thin CLI wrapper around `vet()`. No flags beyond what `vet()` itself
exposes -- if the CLI needs a flag `vet()` doesn't have, the flag belongs
on `vet()` first.
"""

from __future__ import annotations

import argparse
import sys

from ._container import DockerUnavailableError, ImageBuildError
from .core import vet


def _print_events(events: list[dict], *, open_label: str, blocked_label: str) -> None:
    if not events:
        print("  no events observed")
        return
    for event in events:
        flag = blocked_label if event["blocked"] else open_label
        print(f"  [{event['type']}] {event['detail']} ({flag})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="escrow",
        description=(
            "Vet a PyPI package before installing it for real: install and "
            "import it in a sandbox first, and report what it does."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    vet_parser = subparsers.add_parser("vet", help="Vet a package before installing it for real.")
    vet_parser.add_argument("package")
    vet_parser.add_argument("--version", default=None, help="Pin to a specific version.")
    vet_parser.add_argument(
        "--install-timeout", type=int, default=180,
        help="Wall-clock seconds before Phase 1 (install) is killed (default: 180).",
    )
    vet_parser.add_argument(
        "--runtime-timeout", type=int, default=30,
        help="Wall-clock seconds before Phase 2 (import) is killed (default: 30).",
    )

    args = parser.parse_args(argv)

    if args.command == "vet":
        try:
            report = vet(
                args.package,
                args.version,
                install_timeout=args.install_timeout,
                runtime_timeout=args.runtime_timeout,
            )
        except (DockerUnavailableError, ImageBuildError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        print(f"=== registry: {report.package}" + (f"=={report.version}" if report.version else "") + " ===")
        if report.registry_error:
            print(f"  registry check failed: {report.registry_error}")
        else:
            print(f"  exists: {report.registry_exists}")
            print(f"  created: {report.registry_created}")
            print(f"  download_estimate: {report.registry_download_estimate}")

        print()
        print(f"=== phase 1: install (network allowed) -- exit_code={report.install_exit_code} ===")
        print("    events below are what actually happened; network access was open.")
        _print_events(report.install_events, open_label="allowed", blocked_label="blocked")

        print()
        print(f"=== phase 2: import (network off) -- exit_code={report.runtime_exit_code} ===")
        print("    events below are what was attempted; network access was off.")
        _print_events(report.runtime_events, open_label="not blocked", blocked_label="blocked")

        return 0 if report.install_exit_code == 0 else (report.install_exit_code or 1)

    return 2


if __name__ == "__main__":
    sys.exit(main())
