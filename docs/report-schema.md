# Investigation report schema v1

JSON root schema identifier: `trust-the-process/investigation/v1`. UTF-8; timestamps are ISO 8601 with UTC offsets. Reports are snapshots of bounded retained evidence, not full forensic disk images or complete traffic logs. JSON export uses an atomic temporary-file replacement.

| Root field | Meaning |
| --- | --- |
| `schema` | Versioned report contract |
| `generated_at` | Export timestamp |
| `simulated` | True only for synthetic demo data |
| `redacted` | Whether identifying free text/IDs/endpoints were removed |
| `limitations` | Visibility and scoring limitations |
| `process_key` | Selected lifetime identity, if an investigation |
| `current_process` | Current Process fields, or null if no longer present |
| `current_connections` | Current observed endpoints for the selected lifetime |
| `baseline` | Sample counts, robust CPU/RSS/socket statistics, learned features |
| `observations` | Up to 120 persisted process samples, oldest to newest |
| `connections` | Up to 500 socket episodes, most recently observed first |
| `findings` | Retained findings for the lifetime; global export includes up to 10,000 |
| `history` | Global export: latest 120 persisted system frames, oldest first |

`current_process` includes PID, creation time, PPID, name, path, command, user, CPU percent, RSS bytes, memory share, status, SHA-256, file metadata identity, verified parent identity/lifetime, observed socket count, public destinations, remote ports, new remote tuples, and unavailable-field limitations. Null indicates missing measurement. A socket record includes protocol, endpoints, connection state, PID/verified lifetime where known, address classification, first and last observed, source, and new-tuple state. Endpoint fields are observations, not actual socket start/end or packet counts.

Finding fields include deterministic `id`, stable `rule_id`, title, first `timestamp`, `last_seen`, process lifetime/identity/name, category, weight, observed/expected behavior, evidence object, explanation, recommendation, source, confidence/limitations, simulated flag, acknowledgment, and occurrence count. Nested evidence varies by rule; consumers should preserve unknown fields. See [detection](detection.md) for rule contracts.

CSV exports one finding per row, with UTF-8 BOM for Windows spreadsheet compatibility. Nested evidence uses JSON in a cell. Formula-leading strings are escaped with an apostrophe. CSV columns include the finding identity, rule, title, timestamps, process identity/name, severity/weight, observed/expected/evidence, explanation/recommendation, source/confidence/limitations, simulated/acknowledged flags, and occurrences.

Redacted reports replace identifying values and free text with `[REDACTED]`, including hashes, lifetime IDs, PIDs, usernames, paths, commands, endpoint addresses/ports, destination lists, and narrative text that may repeat them. Structured metrics/counts, timestamps, rule IDs, categories, source, protocol, status, and application-authored limitation text remain. Consumers must accept redaction strings where raw data normally contains numbers (for example PID). The redacted format is intended for cautious human review and aggregate demonstrations, not round-trip reconstruction.

