"""The audit-hook watcher, baked into both sandbox images as
`sitecustomize.py` (see Dockerfile.install / Dockerfile.runtime) so it
auto-loads at interpreter startup via Python's own `site` module --
reusing witness's four event categories and exclusions
(witness/witness/watcher.py) almost verbatim, but as a real file dropped
into site-packages rather than a text preamble prepended to one script.

That difference is deliberate and is the whole reason escrow needs its
own variant of the technique rather than importing witness's: witness's
untrusted code is a single script sharing one interpreter process with a
hand-prepended preamble, so text-prepending is enough. escrow's Phase 1
watches a `pip install` that spawns its own subprocess(es) to run a
package's `setup.py` / PEP 517 build backend -- a *new* interpreter
process a prepended string could never reach into. Auto-loading via
`sitecustomize` reaches every one of those child processes too, since
each one is a fresh `python` invocation that goes through normal site
initialization.

Because of that, whether this file's hook actually activates for a given
process is controlled entirely by whether *that* process's interpreter
does normal site processing:

- Phase 1's driver process runs under `python3 -S` (site processing
  skipped) specifically so its own bookkeeping -- spawning `pip` -- isn't
  itself reported as a "process_spawn" event. `pip` and everything it
  spawns in turn (the build backend, `setup.py`) run as plain `python3`
  subprocesses with normal site processing, so they pick this up
  automatically.
- Phase 2's driver process runs under plain `python3`, because it *is*
  the process that does `import <package>` directly -- this hook needs to
  be active for that top-level process itself.

See Dockerfile.install / Dockerfile.runtime for exactly where this file
is copied to and which entrypoint each image uses.

Events are written to a JSONL file rather than directly to this process's
own stdout/stderr, because the whole point is to observe processes other
than the one escrow's own driver script controls directly -- there is no
single stream to print to that's guaranteed to reach the host across a
subprocess boundary the way a shared file does.
"""

from __future__ import annotations

import json
import os
import sys

_EVENTS_PATH = os.environ.get("ESCROW_EVENTS_PATH", "/tmp/escrow_events.jsonl")


def _emit(event_type: str, detail: str) -> None:
    try:
        with open(_EVENTS_PATH, "a") as f:
            f.write(json.dumps({"type": event_type, "detail": detail}) + "\n")
    except Exception:
        pass


def _hook(event: str, args) -> None:
    # NOTE: os.setuid/os.setgid/os.chroot and the rest of that family
    # raise no audit event at all in CPython -- see witness's README for
    # why that's a real, documented gap and not an oversight here either.
    try:
        if event == "socket.connect":
            address = args[1]
            _emit("network", "connect to " + repr(address))
        elif event == "socket.getaddrinfo":
            host, port = args[0], args[1]
            _emit("network", "resolve " + repr(host) + ":" + repr(port))
        elif event == "open":
            path, mode, flags = args[0], args[1], args[2]
            if not isinstance(path, (str, bytes, os.PathLike)):
                return
            write_flags = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
            )
            write_intent = bool(flags & write_flags) or (
                isinstance(mode, str) and any(c in mode for c in "wax+")
            )
            if not write_intent:
                return
            abspath = os.path.abspath(os.fspath(path))
            if abspath == "/tmp" or abspath.startswith("/tmp/"):
                return
            if abspath in ("/dev/null", "/dev/tty"):
                return
            _emit("fs_write", abspath)
        elif event == "os.system":
            _emit("process_spawn", "os.system: " + repr(args[0]))
        elif event == "subprocess.Popen":
            executable, popen_args = args[0], args[1]
            detail = popen_args if popen_args else executable
            _emit("process_spawn", "subprocess.Popen: " + repr(detail))
        elif event == "os.posix_spawn":
            path, argv = args[0], args[1]
            _emit("process_spawn", "os.posix_spawn: " + repr(argv))
        elif event == "ctypes.dlopen":
            _emit(
                "opaque_escape_hatch",
                "ctypes.dlopen used -- subsequent behavior not observable by this tool",
            )
    except Exception:
        pass


sys.addaudithook(_hook)
