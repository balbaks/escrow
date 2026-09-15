"""escrow test fixture: models the real litellm compromise's *mechanism*
(MALWARE_EVALUATION.md) -- a .pth file shipped at the top level of
site-packages, entirely outside the package directory, whose single
`import`-prefixed line Python's own site module auto-executes at
interpreter startup. Not the real payload: this one attempts a connection
to an RFC 5737 TEST-NET-3 address (see pth_trigger_marker.pth), the same
deterministic, non-routable marker action malicious_import_hook already
uses for Phase 2's own network-detection test.

`data_files=[("", [...])]` is the standard setuptools mechanism for
shipping a file at the *root* of wherever it's installed -- the same
mechanism setuptools itself uses to install its own `distutils-
precedence.pth` alongside every setuptools install -- so this lands at the
top level of Phase 1's --target directory, not inside pth_trigger/.
"""

from setuptools import setup

setup(
    name="pth-trigger",
    version="0.1.0",
    packages=["pth_trigger"],
    data_files=[("", ["pth_trigger_marker.pth"])],
)
