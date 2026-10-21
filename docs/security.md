# Security model and operational limits

The app helps an interactive user examine the local host. It reads host process/socket information and executable files, writes local SQLite/preferences/logs, and creates reports only when requested. Optional HTTPS reputation lookups are explicit and indicator-only. It does not change monitored processes, system configuration, services, or scheduled tasks.

Threats considered include misleading names/paths, anomalous changes in a learned workload, process/socket races, inaccessible fields, tainted display strings, CSV formula injection, secret leakage in HTTP errors, and accidental disclosure through reports. Display/export strings remove control characters and bidirectional override characters; CSV cells beginning with spreadsheet formula prefixes are escaped. Reports offer deliberately aggressive free-text and identifier redaction. SQLite statements use parameters for observed values; no telemetry is interpreted as executable commands. The app never launches a shell based on data.

This is not tamper-resistant endpoint security. An attacker with the user's rights can manipulate inputs, data files, preferences, or the app itself. Kernel compromise, injected code, short-lived execution, protected-process internals, packet payloads, and pre-observation history are outside visibility. Metadata and hashes describe the current on-disk file, not necessarily the image that was loaded into memory. Permission failures and missing measurements are limitations, never findings by themselves.

## Local privacy

The default data directory inherits the user's Windows account permissions. It is not encrypted by this application. Command lines can include secrets; avoid collecting real host data during public demonstrations. Reports are user-selected local writes. Unredacted exports include sensitive paths, usernames, command lines, IPs, and hashes. Default redaction removes all identifying free text, stable identifiers, endpoints, and ports, including duplicated narrative evidence. Timestamps, metrics, rule IDs, and behavior can remain sensitive. Redaction is a sharing aid, not a guarantee of anonymity.

Logs use bounded rotation and operational error classes. No API key is stored by application code in the preferences/database/logs or sent to any endpoint except that provider's HTTPS key header. Keys exist in process environment/memory and can be visible to a sufficiently privileged local user. This version does not integrate Windows Credential Manager.

History retention defaults to 14 days, with caps of 200,000 process observations, 10,000 frames, 50,000 socket episodes, 10,000 findings, and 5,000 executable baselines. Pruning runs on startup/first observation and about every minute. SQLite reuses deleted pages; the file may retain its high-water allocation and deletion is not secure erasure. WAL files are local and should not be shared. Capturing many high-cardinality sockets or very long command lines can increase storage within these caps.

## Reputation providers

Both providers are disabled by default, and all requests remain manual. Public IPs and strict SHA-256 strings are the only accepted indicator shapes; AbuseIPDB supports IPs only. Hosts/domains/URLs, private addresses, scoped IPs, documentation ranges, loopback, multicast, and special addresses are rejected. IPv4-mapped IPv6 addresses receive IPv4 classification. Lookups follow no redirects and use fixed provider origins and GET endpoints. No file content or other local telemetry is sent.

An indicator lookup also discloses the client source IP to the provider. VirusTotal warns that queried indicators may enter its dataset. Provider settings explain this before opt-in. The local demo mock never contacts a service, and all fake findings carry simulated flags. Cache results are attributed with original lookup timestamps; a cache hit does not imply fresh analysis. An HTTP error, timeout, malformed report, or 404 never produces an adverse finding.

Default success/not-found caching is 24 hours, configurable through the preferences file (1–168 hours). Cache hits retain their original expiry and lookup time. Equivalent IP spellings and hash capitalization use the same cache entry. Errors use a provider cooldown rather than pretending to be a clean result. VirusTotal is throttled to one attempted request per 16 seconds and 500 local attempts per UTC day; AbuseIPDB to one per three seconds. HTTP 429 applies at least 60 seconds of cooldown, respecting numeric and HTTP-date Retry-After values up to one day. Invalid headers fall back to 60 seconds. Limits are persisted across restarts. Other users of the same key also consume quota, and service-side 429 may require longer waiting.

Implementation references reviewed during development: [VirusTotal file report](https://docs.virustotal.com/reference/file-info), [IP report and dataset warning](https://docs.virustotal.com/reference/ip-info), [Public/Premium restrictions](https://docs.virustotal.com/reference/public-vs-premium-api), [AbuseIPDB APIv2](https://docs.abuseipdb.com/), and [AbuseIPDB terms](https://www.abuseipdb.com/legal). Check current provider terms before use. The MIT software license does not grant rights to external services or reputation data.

## Windows and extensions

Ordinary collection requests no administrator privileges. Some protected executables, users, command lines, socket owners, or whole network snapshots may be unavailable. Elevation can improve visibility but is not a requirement or a cure for races. The app does not prompt for elevation.

The network adapter protocol explicitly exposes source/capabilities. Future Sysmon support should read an existing installation's events, disclose required channel permissions, preserve event record identifiers, distinguish event time from observation time, and never install/reconfigure the sensor silently. Future tuple-correlated packet attribution must be labeled inferred. Those extensions are not included in v0.1.

