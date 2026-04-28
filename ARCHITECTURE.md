# Flows

Top-to-bottom flow charts for the main paths through the system. All
diagrams are [Mermaid](https://mermaid.js.org/) — they render natively on
GitHub and in modern Markdown viewers.

---

## Service startup

```mermaid
flowchart TD
    A[python main.py]
    B[Cold-start batch<br/>process last --since-days<br/>only if --since-days set]
    C[Spawn background poller<br/>daemon thread]
    D[Boot uvicorn]
    E[Service ready on<br/>http://host:port]

    A --> B --> C --> D --> E
```

---

## On-demand triage — POST /classify

```mermaid
flowchart TD
    A[POST /classify with cve_ids]
    B[agent.run<br/>SYSTEM_INSTRUCTIONS_BY_ID]
    C[Agent calls fetch_security_data]
    D[Agent classifies each CVE]
    E[Agent calls store_findings]
    F[Agent calls send_critical_alert]
    G[Return JSON with agent response]

    A --> B --> C --> D --> E --> F --> G
```

---

## Cold-start batch / periodic poll

Same flow, two triggers — the optional cold-start on service startup and
the background poller thread (every `--poll-interval` seconds).

```mermaid
flowchart TD
    A[Trigger: cold-start or poller tick]
    B[run_batch<br/>since_days or watermark]
    C[Fetch one NVD page]
    D[Dedup against DB<br/>by source_last_modified]
    E[For each batch of survivors:<br/>agent.run with SYSTEM_INSTRUCTIONS_BATCH]
    F[Agent: classify → store_findings → send_critical_alert]
    G{More pages?}
    H[Done]

    A --> B --> C --> D --> E --> F --> G
    G -- yes --> C
    G -- no --> H
```

---

## The agent loop

Same cycle for both flows — the only difference is which `system_prompt`
the caller passes.

```mermaid
flowchart TD
    A[user_request + system_prompt]
    B[Send to LLM with TOOLS]
    C{tool_calls?}
    D[Execute each via TOOL_DISPATCH]
    E[Append tool_results to messages]
    F[Return final text]

    A --> B --> C
    C -- yes --> D --> E --> B
    C -- no --> F
```
