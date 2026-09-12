"""The marker-line technique, reused from witness: a per-run marker,
generated fresh and unknown to whatever runs inside the container ahead
of time, prefixes every structured line a phase's driver script emits.
That makes it possible to tell those lines apart from the container's
real output unambiguously -- and unfakeably, since nothing running inside
the container can predict or forge the marker.

escrow uses this for two distinct purposes per phase, both on the
container's own stdout/stderr rather than a second channel:

- structured behavior events (read back from the JSONL file
  `escrow/sandbox_hook.py`'s audit hook writes to, then re-emitted by the
  driver script as marker-prefixed lines on stderr)
- Phase 1's installed-package artifact, handed to Phase 2 as a
  marker-prefixed base64 blob on stdout

`split_marked` is the one primitive both uses share; `parse_events` and
`_BLOCK_SIGNATURES` turn parsed event lines into the `blocked`-annotated
dicts both `install_phase.py` and `runtime_phase.py` return.
"""

from __future__ import annotations

import json
import uuid

MARKER_PREFIX = "ESCROW"

# Substrings that indicate the sandbox's own OS-level isolation -- not the
# audit hook, which never blocks anything -- is what actually stopped an
# attempted operation. Used to fill in `blocked` after the fact from a
# phase's real (non-marker) stderr. Heuristic, not exact: the audit hook
# fires *before* the outcome is known, so this is the only way to
# attribute "blocked" without changing what the hook itself does. Reused
# from witness/witness/docker_runner.py unmodified.
_BLOCK_SIGNATURES = {
    "network": (
        "Network is unreachable",
        "Name or service not known",
        "Temporary failure in name resolution",
        "gaierror",
        "URLError",
        "Connection refused",
    ),
    "fs_write": (
        "Read-only file system",
        "Permission denied",
    ),
    "process_spawn": (
        "Operation not permitted",
        "PermissionError",
        "BlockingIOError",
    ),
    # A dlopen call succeeding is exactly what makes this category opaque
    # in the first place -- whatever happens after it is invisible to
    # escrow, so it never claims to know it was blocked.
    "opaque_escape_hatch": (),
}


def generate_marker() -> str:
    """A fresh, per-run marker unknown ahead of time to anything running
    inside the container -- same unambiguous, unfakeable-sentinel
    principle husk/witness use."""
    return f"{MARKER_PREFIX}_{uuid.uuid4().hex[:8]}_"


def split_marked(text: str, marker: str, tag: str) -> tuple[str, list[str]]:
    """Pull every line prefixed with `marker + tag + ":"` out of `text`.

    Returns `(remaining_text, [payloads])` -- `remaining_text` is what's
    left once those lines are removed, i.e. the stream's real content.
    """
    prefix = f"{marker}{tag}:"
    remaining: list[str] = []
    matched: list[str] = []
    for line in text.split("\n"):
        if line.startswith(prefix):
            matched.append(line[len(prefix):])
        else:
            remaining.append(line)
    return "\n".join(remaining), matched


def parse_events(event_lines: list[str], real_stderr: str) -> list[dict]:
    """Decode marker-payload JSON lines (one per behavior event) into
    `{"type", "detail", "blocked"}` dicts, attributing `blocked` from the
    phase's real (non-marker) stderr."""
    events = []
    for line in event_lines:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_type = raw.get("type", "")
        detail = raw.get("detail", "")
        blocked = any(sig in real_stderr for sig in _BLOCK_SIGNATURES.get(event_type, ()))
        events.append({"type": event_type, "detail": detail, "blocked": blocked})
    return events
