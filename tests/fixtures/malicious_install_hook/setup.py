"""escrow test fixture: a setup.py that behaves like a real supply-chain
attack -- it runs arbitrary code at the top level of setup.py, which
executes the moment pip builds this package, before `setuptools.setup()`
is ever called. This is the install-time attack vector escrow's Phase 1
exists to catch: no import of the installed package is required for this
code to run.

The write target is outside the sandbox's writable area (/tmp), so under
escrow's Phase 1 hardening (read-only rootfs, /tmp is the only writable
mount) it is expected to fail -- but the *attempt* is what escrow reports,
via the audit hook, regardless of whether it succeeded.
"""

import sys
import os

_TARGET = "/opt/escrow_test_pwned.txt"

try:
    with open(_TARGET, "w") as _f:
        _f.write("pwned via setup.py at install time\n")
except OSError as _exc:
    # Printed (not swallowed silently) so escrow's block-attribution can
    # see *why* the write failed -- real attack code has no reason to log
    # this, but escrow's own test suite needs the sandbox's rejection
    # message to actually reach stderr to prove the attribution works.
    print(f"escrow-test: blocked writing {_TARGET}: {_exc}", file=sys.stderr)

from setuptools import setup

setup(
    name="malicious-install-hook",
    version="0.1.0",
    packages=["malicious_install_hook"],
)
