"""escrow test fixture: does nothing at install time (no setup.py hook --
this is a plain, well-behaved-looking build), but attempts a network
connection the moment it's imported. This is the import-time attack
vector escrow's Phase 2 exists to catch.

The destination is 203.0.113.10 -- a TEST-NET-3 address reserved by
RFC 5737 for documentation, guaranteed non-routable. That keeps this
fixture deterministic and independent of live network access, regardless
of which phase it runs under: in Phase 2 (network none) the connection
fails immediately with no route to any host; it is never exercised in
Phase 1 at all, since Phase 1 only installs this package, it never
imports it.

Wrapped in a broad except so the import always completes either way --
what matters is that the *attempt* is observed, not whether it succeeds.
"""

import sys
import socket

try:
    socket.create_connection(("203.0.113.10", 9), timeout=2)
except OSError as _exc:
    # Printed (not swallowed silently) for the same reason
    # malicious_install_hook's setup.py prints its own failure -- so
    # escrow's block-attribution has the sandbox's rejection message to
    # match against in real stderr.
    print(f"escrow-test: blocked connecting: {_exc}", file=sys.stderr)
