# dark-factory isolation (standard tier)

`standard` runs the builder AND the candidate under an OS read-denial sandbox that
cannot read the control root (scenarios/runs). Backends: macOS `sandbox-exec`
(`(allow default)(deny file-read* (subpath control_root))`), Linux `bwrap`
(masks the control root with a tmpfs). Windows: no backend yet → unsupported.

A tier is claimed only when **probe-verified**: at startup a canary is planted in
the control root and a wrapped process must fail to read it. If the backend is
missing or the probe fails, the run **fails closed** (exit 2) unless
`--allow-downgrade` drops it to `cooperative` (unqualified) with a warning + a
`DOWNGRADE` audit entry. The Linux backend ships code-complete but is unverified on
the maintainer's macOS machine — the denial probe is the guarantee that it is never
trusted without proof on the actual host.
