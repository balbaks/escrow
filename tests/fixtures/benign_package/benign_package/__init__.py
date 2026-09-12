"""A benign escrow test fixture: no network, no filesystem writes outside
/tmp, no process spawns, on either install or import. The control case --
proves escrow reports a clean package as clean, not just "flags
everything"."""

VALUE = 42
