"""escrow test fixture: a normal, harmless package, installed alongside a
top-level .pth file (pth_trigger_marker.pth) that does the actual work.
Importing this module itself does nothing observable -- the point of this
fixture is that its behavior fires from .pth processing at site-init time,
before anyone ever imports pth_trigger at all, the same shape as the real
litellm compromise (MALWARE_EVALUATION.md): a .pth file shipped outside
the package that Python's own site module auto-executes, independent of
whether the package it sits next to is ever imported.
"""
