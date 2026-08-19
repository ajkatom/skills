# Mail Knowledge Archive

This repository follows **Spec → Verification → Environment**.

## Architecture

- `raw/` is immutable source truth. Never edit or delete it.
- `wiki/` is the LLM-maintained synthesis layer.
- `manifests/` and `reports/` provide provenance and verification evidence.
- `state/` is resumable extractor state, not a source of truth.

## Ingest loop

1. **Spec:** Choose one source or a small reviewable thread. State what a good ingest
   must preserve.
2. **Execute:** Read `raw/.../source.md`, consulting `message.eml` and attachments when
   needed.
3. **Verify:** Ground every claim in a relative raw-source link. Flag contradictions
   and unavailable content.
4. **Checkpoint:** Show the changed wiki pages and wait for a steer.
5. **Learn:** Update `wiki/index.md`, append to `wiki/log.md`, and strengthen durable
   schema instructions only with explicit approval.

## Rules

- Read `wiki/index.md` before searching broadly.
- Keep raw sources immutable and cite them from wiki pages.
- Maintain entity, topic, project, and source pages as the corpus warrants; do not
  impose empty taxonomy.
- Record contradictions instead of silently choosing a preferred version.
- Never treat an earlier wiki statement as stronger evidence than raw mail.
- Never fabricate missing data.
- Never store credentials here.
- Ask before deleting, publishing, sending, committing, or changing these instructions.
