# DB query API review

[Codex] 2026-11-09 — feat/case-query-api

START=40baada (main after saved-case UI merge).

Saved case schema 2 adds query projections, stable event IDs, timeline/artifact/SID/source/tag indexes, optional built-in trigram candidate search, bounded relation summaries and indexed membership. The reader opens the case read-only, copies WAL inputs before opening, and never accesses original evidence. Legacy schemas use read-only compatibility scans. Explicit integrity verification is separate from fast opening.

Validation: 24 query tests and all 708 unittest tests passed; teaching copies: 120 sources, zero differences. Synthetic sample regenerated with example/samples/demo.py. No GUI code changed. Large-case performance and real evidence/image environments were not measured in this stage.

Push review: new paths and added lines checked; no external reference code/data, forbidden names, private paths, evidence, outputs or runtime dependencies added. Original JSON event payloads and forensic interpretation remain unchanged. Stable sort/filter/search equivalence, corruption warnings, WAL preservation and bounded membership reads covered by tests. No blocking findings in self-review.
