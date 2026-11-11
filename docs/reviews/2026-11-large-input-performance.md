# Large-input engine performance

START=e748ed69ae416317f10e4a39def48c3efc53a1e1

## Changes

Entity lists are serialized once per entity within the existing transaction. Overlapping qualifying 60-second burst windows become one interval; event_count counts its records and peak_window_count measures peak density. Correlation timestamps are parsed once per distinct value per analysis. Path/URL candidates are partitioned by artifact and SID, with exact compatible counts computed without enumerating pairs. Deletion candidates use a filename index and bipartite SID-compatible counts. USB candidates use sorted clock-specific integer microsecond positions and inclusive 300-second bisect windows; overlapping ranges are unioned without expanding every pair.

More than 10000 candidates in a path/URL/deletion group, or across USB windows, are stored as correlation_group with candidate_count/event_indices/relation_type/pair_expansion_limit. USB/deletion groups include left_event_indices; USB additionally records window_seconds and same_clock_required. Group membership alone does not imply every pair is related or confirm execution. Existing small-input relations retain ordering and meaning. New relation label is additive. UI/report display follow-up: issue #29.

## Validation

Full unittest suite: 226 passed. Failing regressions were observed before each corresponding correction. A nine-artifact small input retained all 102 relation dictionaries exactly. Same timestamp across 100 execution artifacts needed 5100 parses before, one after. SID conflicts, missing SIDs, timezone offsets, unknown clocks, microsecond boundaries, dense groups and separate burst intervals are covered.

Windows/Python 3.15 single-run measurements (not universal performance guarantees):

| Input | Before | After |
| --- | --- | --- |
| 20000 events sharing SID, in-memory SQLite | 3.6933s | 0.1326s |
| 4000 events spaced 0.1s, burst detection | 1.4978s / 3400 warnings | 0.0063s / one interval |
| 4000 same-name cross-artifact events | 4000000 pair dictionaries | one group, 4000000 candidates |

The final same-name workload measured 0.0607s and 1.358MiB peak Python allocations under tracemalloc; this excludes input creation and is not process RSS. Actual CLI with 150 generated task files and 150 generated startup scripts produced 300 events, zero errors and a 22500-candidate group. Report JSON relations equalled SQLite relations exactly; all source SHA-256 hashes remained unchanged. Command shape: python -m log_hunter analyze --input tasks <synthetic-tasks> --input startup <synthetic-startup> --output <empty-output>.

Not verified: real evidence, all OS variants, real disk SQLite benchmarks, GUI rendering. MountPoints2 matching retains its existing implementation; this change addresses the three reported hotspots and path/URL/USB/deletion expansion, not every possible future correlation strategy. Burst warnings and dense relation representation intentionally change; consumers must distinguish groups from pairs. Push review inspected new files, added lines and commit messages; no runtime dependencies or source evidence added.
