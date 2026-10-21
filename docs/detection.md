# Detection, learning, and evidence scores

Rules compare a snapshot to the **previous** learned state, then learning advances. Five features are relevant to interpretation:

1. A process lifetime is PID plus creation time. Unknown creation times do not imply stable ownership. File baselines require an executable path and readable regular-file metadata.
2. Learning uses machine-local observations, grouped by full path and file metadata, not filename. Each poll contributes the maximum available value among concurrent instances. Multi-instance applications may have a wider baseline than an individual process.
3. Default maturity is 20 polls. Resource and network rules additionally require 20 valid samples of their respective metric. Unavailable values do not count. Baseline state persists across restarts; retained values use a rolling 120-sample window, while distinct destinations/ports/parents are recency-bounded to 512 each. Baselines are time-retained and capped to 5,000 identities.
4. Resource anomalies must remain above threshold for three consecutive observed samples of the same process lifetime. Missing or normal samples reset the streak. Mature resource outliers are excluded from learning, even before a finding fires, preventing immediate baseline contamination. A legitimate persistent workload change may need a baseline reset.
5. New features are learned after comparison. Network/parent novelty can therefore produce a single recorded finding and remain visible in history without repeatedly alerting forever. Acknowledgment changes review state, not evidence or score.

## Rules

| ID | Weight | Trigger / expectation |
| --- | ---: | --- |
| RES-MEM | 10 | Sustained RSS above the maximum of median × 2.5, median + 100 MiB, and p95 + 6 × MAD |
| RES-CPU | 10 | Sustained CPU above max(p95 + 40 percentage points, median + 6 × MAD) |
| EXEC-TEMP | 10 | Executable path contains a temporary/download directory component; no baseline needed |
| EXEC-SYSTEM | 30 | One of five common Windows service/session executable names outside System32/SysWOW64 under SystemRoot |
| EXEC-PARENT | 10 | Verified parent executable identity absent from a mature, nonempty parent history |
| EXEC-CHANGE | 10 | First observation of changed file metadata at a previously known path; updates are a common cause |
| NET-FIRST | 20 | Public destinations observed after a mature, valid network baseline with none |
| NET-DEST | 20 | At least five public destinations absent from learned history in one snapshot |
| NET-BURST | 15 | At least five newly observed remote socket tuples and concurrency > max(2 × p95, p95 + 3) |
| CTX-TEMP-NET | 20 | Transient executable plus one of the established-baseline network changes above |
| TI-REPUTATION | 40 | Manually retrieved provider context: ≥3 VirusTotal malicious engine reports, or AbuseIPDB score ≥75 with reports; demo uses an explicit local mock |

MAD is the median absolute deviation. p95 is the sorted value at `floor((n-1) × .95)`; small samples are deliberately gated. Connection activity evidence includes the measured time between snapshot starts, rather than treating the configured wait as elapsed observation time. Collection work adds time to the configured wait. Counts do not represent traffic volume. Network outages contribute no baseline network samples and do not create evidence. The first successful snapshot, and the first snapshot after a pause or network outage, is inventory rather than a burst of new sockets.

Memory multiplier, minimum MiB delta, CPU delta, sample/streak requirements, baseline window, and connection/destination thresholds can be changed in Settings or non-secret configuration. Rule registration uses `Detector.rules`, a list of callables from `(Process, Snapshot)` to findings; new rules should add a stable ID and documented evidence weight in `RULES`. All rules must tolerate missing telemetry.

## Score and severity

The process evidence score is `min(100, sum(max recorded weight for each distinct rule)))` for the selected **process lifetime**. Repeated findings do not add weight. Acknowledged or currently resolved findings remain part of that lifetime's investigation context. A new PID lifetime starts a separate score. History retention bounds how long evidence is available. Scores and live process details use all retained findings for that process. The global Findings page filters and sorts across all retained findings and displays 200 per page. Exports can include up to 10,000.

Categories: **Informational 0–9**, **Low 10–29**, **Medium 30–59**, **High 60–100**. Each finding has a category for its own weight; the aggregate process score may have a higher category. This is a documented triage heuristic, not a scientifically calibrated probability, a verdict, or independent evidence. Correlated rules intentionally add contextual weight; they must not be interpreted as statistically independent signals.

Evidence weights are configurable in the local `config.json` with `"rule_weights": {"EXEC-TEMP": 5, "NET-FIRST": 25}`. Omitted rule IDs use the defaults above. Overrides must use known rule IDs and integer values from 0 to 100; zero gives an informational finding with no score contribution. Preferences are read at launch. Weight changes apply to newly generated/updated findings; existing historical records keep the weights under which they were recorded. Resource or network findings remain contextual even if you choose a larger weight.

Finding IDs deduplicate `(rule ID, process lifetime, simulated flag)`. Reputation findings additionally distinguish provider and indicator, preserving separate reports for different destinations. The first timestamp is retained, last observed is updated, occurrences count observations (or manual reputation reviews), and acknowledgment persists. Reputation results retain the process context captured when requested, even if it exits before the request finishes. A finding contains process identity, observations, expectations when available, structured evidence, source, limitations, confidence wording, explanation, and investigation recommendations. Provider feedback remains contextual and can be incorrect or stale.

Version 0.1 does not authenticate publishers, validate signatures, examine process memory, detect all user-writable locations, or distinguish every legitimate workload. Path heuristics deliberately cover transient/download directories; AppData applications in general are not flagged for their install location. An unseen executable is shown as **Learning / Insufficient Baseline** rather than declared suspicious merely for being new.

