# Knowledge-base integration (optional, spec §3A)

dark-factory is self-contained; a KB is optional and never required.

- **wiki** (`knowledge_base.kind: wiki`, `path: <dir>`): with `write_back: true`
  the supervisor appends a **barrier-safe** run summary to
  `<path>/dark-factory-runs.md` at each terminal — only `outcome`, `tier`,
  `qualified`, `iterations`, and failing **behavior IDs**. No scenario text,
  observed output, or prompts. A KB write-back failure never changes the run's
  exit code (it journals `KB_WRITEBACK_ERROR` and continues).
- **open-brain** (`kind: open-brain`): the supervisor does nothing — MCP is a
  Claude-session capability. This session may read it for grounding and, only on
  the user's OK, `capture_thought` the outcome.
- **none** (default): fully standalone.

Reading a KB for grounding is always this session's job; the supervisor only ever
*writes* the wiki summary, and only when opted in.
