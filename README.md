# escrow

escrow vets a Python package before you ever run a real `pip install` on
it: it actually installs and imports the package inside a sandbox first,
and reports what it did.

```python
from escrow import vet

report = vet("some-package", version="1.2.3")
print(report.install_events)   # what happened -- network was open
print(report.runtime_events)   # what was attempted -- network was off
```

This exists because LLMs hallucinate plausible-but-nonexistent package
names at meaningful rates, attackers register those exact names on PyPI
("slopsquatting"), and the next `pip install` executes whatever they put
there. Existing defenses in this space are pre-install static checks --
does the name exist, is it new. escrow's job is different and harder:
detonate it first, and report what actually happened.

## The wall -- read this first

**Phase 1 needs network access to install for real.** A real `pip
install` can run arbitrary code via `setup.py` / build hooks, and that
requires reaching the package index. This means: anything malicious that
completes fast enough during the install window -- for example,
exfiltrating environment variables before this tool even finishes
generating its report -- cannot be prevented in real time. escrow can
only detect and report it after the fact. It is an audit tool for the
install step, not a firewall for it. This is a fundamental limit of
vetting something that requires network access to install at all, not a
bug to be engineered around in v0.1.0 -- stated here plainly, the same way
[husk](../husk) states its shared-kernel limit and
[witness](../witness) states its `ctypes` blind spot.

A second, smaller limit: a single, short detonation pass cannot catch a
sandbox-aware or time-delayed payload that behaves innocently during the
test and activates later. One clean report is evidence, not a guarantee.

## The two-phase mechanism

**Registry check** (cheap, first, no sandbox): a read-only query against
PyPI's JSON API for existence, creation date, and (see below) download
volume. A fast early signal, not a verdict on its own.

**Phase 1 -- install, network allowed, fully observed.** Real installs
need network, which conflicts with husk's default no-network hardening.
So Phase 1 uses its own sandbox variant (`Dockerfile.install`): every
other husk hardening flag stays on -- non-root, dropped capabilities,
read-only rootfs with only `/tmp` writable, resource limits, `--rm`,
host-side timeout -- but network is allowed, specifically so the install
can complete. A witness-style audit hook, baked into the image as
`sitecustomize.py`, observes and reports everything attempted during
install -- network destinations, file writes outside the sandbox's
writable area, process spawns -- regardless of whether they'd be blocked
under stricter hardening. Because the hook is a real file auto-loaded by
Python's own `site` module rather than a text preamble prepended to one
script (witness's original technique), it reaches every subprocess `pip`
spawns to build the package too -- including the `setup.py` / PEP 517
build-backend subprocess where install-time attacks actually run -- not
just the top-level driver process. `install_events` is the result: what
*actually happened*, since network was open.

**Phase 2 -- fresh container, import only, full husk hardening.** A
completely new container, husk's normal fully-hardened profile, no
network at all. The files Phase 1 installed are handed over as a tarball
embedded directly in this phase's driver script -- no host path is ever
bind-mounted in, same principle husk and witness use for code. The same
audit hook observes the same categories while the package is merely
`import`ed (nothing else is called into). `runtime_events` is the result:
what was *attempted*, since network was off here.

**These two event lists are kept separate on purpose, never merged.**
`install_events` is proof of action -- it's what really happened, because
network was open. `runtime_events` is proof of intent -- what the package
tried and had blocked, because network was closed. A network event
appearing in both lists tells you something different each time:
collapsing them into one report would erase that distinction.

## Relationship to husk and witness

escrow composes both projects' techniques rather than reinventing either.
It reuses husk's hardening flags (non-root, dropped capabilities,
read-only rootfs, resource limits, `--rm`, host-side timeout) as the base
for both of its own Dockerfiles, adding only the one change each phase
needs (network on for Phase 1, husk's original network-off for Phase 2).
It reuses witness's core insight -- a Python audit hook observes intent
*before* the sandbox's own isolation gets a chance to allow or deny it --
but ships it as a real `sitecustomize.py` file rather than a
text-prepended preamble, because escrow has to observe subprocesses
(`pip`'s build backend) that a prepended string could never reach into.
See [`escrow/sandbox_hook.py`](escrow/sandbox_hook.py) for exactly how
that's scoped per phase.

## What the registry check does and doesn't tell you

Existence, creation date, and download volume, from PyPI's JSON API --
that's it for v0.1.0. No fuzzy name-similarity-to-popular-package
heuristics (catching e.g. a hallucinated near-miss of a popular package
name) -- that's a real future direction, deliberately deferred.

`download_estimate` is always `None`. PyPI's JSON API `downloads` field
has been a permanently deprecated placeholder (`-1`) for years; rather
than report a number pulled from a second, unrelated service (like
pypistats.org) with its own availability and rate-limit failure modes,
this tool doesn't fabricate one. Wiring up a real download-volume source
is future work.

`registry_exists` is `bool | None`, and the `None` case is deliberate: a
real 404 from PyPI (`exists=False`, `error=None`) is a confident
negative, but an unreachable API, a timeout, a 5xx, or an unparseable
response (`exists=None`, `error` set) means the check itself could not be
completed. These are not the same signal, and this tool never collapses
them into one -- a transient network failure while checking the registry
must never be reported as though it were a confident "this package does
not exist", which is exactly the ambiguity a hallucinated-package check
exists to resolve, not introduce. See
[`tests/test_registry_checks.py`](tests/test_registry_checks.py) for the
proof: the real-404 case and the mocked-failure cases are asserted as
distinct states.

## Scope (v0.1.0)

- PyPI / `pip` only. No npm, no other ecosystem.
- One public entrypoint, `vet()`, returning a `VettingReport`: registry
  metadata plus the two phases' event lists, kept distinct.
- Python packages only -- same boundary husk and witness draw.

## Safety note

Never point this tool's own test fixtures at a real, unknown package as a
substitute for actually vetting one -- they're small, deliberately
misbehaving local packages built to prove the detection logic works, not
a corpus of real-world threats. And before vetting a genuinely unknown
package for real, re-read "The wall" above: a clean report means nothing
malicious was *observed* in one short run with network open, not that
nothing happened. The test suite obeys the same rule it asks of you: it
never installs a real, live, unknown third-party package.
[`tests/fixtures/`](tests/fixtures/) holds the three local packages
(`benign_package`, `malicious_install_hook`, `malicious_import_hook`)
every install/import test in this repo installs from a local path --
never the live PyPI. The one exception is
[`tests/test_registry_checks.py`](tests/test_registry_checks.py), which
queries the real PyPI JSON API read-only, against a known, real, benign
package (`requests`) -- a metadata read, not an install.

## Usage

### Library

```python
from escrow import vet

report = vet("requests", version="2.31.0")

print(report.registry_exists, report.registry_created)

for event in report.install_events:
    print("install:", event["type"], event["detail"], event["blocked"])

for event in report.runtime_events:
    print("import:", event["type"], event["detail"], event["blocked"])
```

### CLI

```console
$ escrow vet requests --version 2.31.0
=== registry: requests==2.31.0 ===
  exists: True
  created: 2011-02-14T...
  download_estimate: None

=== phase 1: install (network allowed) -- exit_code=0 ===
    events below are what actually happened; network access was open.
  [network] resolve 'pypi.org':443 (allowed)
  [network] connect to (...) (allowed)

=== phase 2: import (network off) -- exit_code=0 ===
    events below are what was attempted; network access was off.
  no events observed
```

That's the "everything's fine" case. The actual motivating scenario --
an LLM hallucinates a package name that doesn't exist -- looks like this.
Real, unedited output from a real run against a genuinely nonexistent
name:

```console
$ escrow vet this-package-definitely-does-not-exist-escrow-test-xyz-987654321
=== registry: this-package-definitely-does-not-exist-escrow-test-xyz-987654321 ===
  exists: False
  created: None
  download_estimate: None

=== phase 1: install (network allowed) -- exit_code=1 ===
    events below are what actually happened; network access was open.
  [process_spawn] subprocess.Popen: ['lsb_release', '-a'] (allowed)
  [process_spawn] subprocess.Popen: ['uname', '-rs'] (allowed)
  [network] resolve 'pypi.org':443 (allowed)
  [network] connect to ('151.101.64.223', 443) (allowed)
  [network] resolve 'pypi.org':443 (allowed)
  [network] connect to ('151.101.64.223', 443) (allowed)

=== phase 2: import (network off) -- exit_code=None ===
    events below are what was attempted; network access was off.
  no events observed
$ echo $?
1
```

`registry_exists=False` is a confident negative here -- this is a real
404, not an unreachable-API ambiguity (see "What the registry check does
and doesn't tell you" above). `pip` still reaches out to PyPI during
Phase 1 (that's `pip` itself checking, not something escrow gates on the
registry result) and gets nothing back to install, so Phase 1 fails
(`exit_code=1`) and Phase 2 never runs at all (`exit_code=None`, no
events) -- there's nothing installed to import. The exit code propagates:
`echo $?` above is `1`, not `0`. This is the exact case that would have
silently executed a slopsquatted payload without a tool sitting in front
of the install.

Exit code mirrors Phase 1's: `0` on a clean install, otherwise the
install's own exit code (Phase 2 never runs if Phase 1 failed -- there's
nothing installed to import).

## Install

```console
pip install -e ".[dev]"
```

Requires local Docker socket access, same adoption friction as husk and
witness. The two sandbox images (`escrow-install:latest`,
`escrow-runtime:latest`) are built automatically from `Dockerfile.install`
/ `Dockerfile.runtime` the first time they're needed, and reused after
that.

## Running the tests

```console
pip install -e ".[dev]"
pytest -v
```

Requires Docker for every test except `test_registry_checks.py`. Each
install/runtime test builds the relevant sandbox image once (cached
across runs), installs or imports one local fixture, and asserts the
specific event that fixture is designed to produce -- not just that
*something* got logged:

| Fixture | Phase | Proves |
|---|---|---|
| [`benign_package`](tests/fixtures/benign_package/) | 1 & 2 | A normal package produces a clean report in both phases -- this isn't "flag everything" |
| [`malicious_install_hook`](tests/fixtures/malicious_install_hook/) | 1 | A `setup.py` file write outside `/tmp` is observed and shown blocked, in [`test_install_phase_detection.py`](tests/test_install_phase_detection.py) |
| [`malicious_import_hook`](tests/fixtures/malicious_import_hook/) | 2 | A network connection attempted on import is observed and shown blocked -- contrast with the same event type in Phase 1, where it would show unblocked -- in [`test_runtime_phase_detection.py`](tests/test_runtime_phase_detection.py) |
| [`pth_trigger`](tests/fixtures/pth_trigger/) | 2 | A top-level `.pth` file's `import`-prefixed line is observed via `site.addsitedir()` -- models the real `litellm` compromise's mechanism (see `MALWARE_EVALUATION.md`), in [`test_runtime_phase_detection.py`](tests/test_runtime_phase_detection.py) |

[`tests/`](tests/) is the proof for every claim in this README.

## Against real malware

The tests above prove escrow's detection logic against fixtures written
to exercise it. [`MALWARE_EVALUATION.md`](MALWARE_EVALUATION.md) runs the
same detection mechanism against 11 real, documented, historical
malicious PyPI packages, sourced from a public research dataset and
detonated inside a network-sinkholed variant of Phase 1 built
specifically for that evaluation -- never the live internet. It found a
real, previously-undocumented architectural gap in Phase 2's own
artifact-loading mechanism: a `.pth`-file payload class Phase 2 could not
see at all, because loading the installed artifact via a plain
`sys.path.insert()` makes the package importable without ever triggering
the `.pth`-file processing real Python site-initialization performs at
interpreter startup.

**Fixed as of v0.1.1.** Phase 2 now loads the artifact via
`site.addsitedir()` instead -- the same primitive real Python uses at
startup -- so a `.pth` file shipped at the top level of the artifact
(exactly where the real `litellm` compromise shipped `litellm_init.pth`)
is now processed the same way a live install would process it. See
[`tests/test_runtime_phase_detection.py::test_pth_triggered_action_is_observed_in_phase_2`](tests/test_runtime_phase_detection.py)
for the regression test (a local, benign fixture modeling the mechanism,
never the real `litellm` sample) and `escrow/runtime_phase.py` for the
fix itself. One narrower limitation survives, inherited from CPython's
own `site` module rather than introduced by this fix: a `.pth` file's
remaining lines stop being processed after the first line that raises --
see `MALWARE_EVALUATION.md`'s v0.1.1 addendum for the honest detail.
Read the full evaluation before trusting a clean report on a package you
don't already know.
