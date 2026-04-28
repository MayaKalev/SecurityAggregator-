# Security Intelligence Aggregator

A backend service that ingests CVEs from NIST NVD, lets an LLM (OpenAI)
classify each one, and persists the findings. The LLM drives the work as
an **agent** by calling MCP-style tools.

The service runs a startup batch (the day so far by default), then keeps
polling NVD on an interval and exposes a small REST API for on-demand
CVE triage.

End-to-end flow charts: see [ARCHITECTURE.md](ARCHITECTURE.md).

## Layout

```
main.py                    # CLI entry — boots the service
service.py                 # FastAPI app: /classify, /findings, /health
agent/
    agent.py               # LLM tool-use loop
    prompts.py             # system prompts (BATCH + BY_ID)
    orchestrator.py        # pagination + dedup + per-batch agent invocation
tools/
    mcp_tools.py           # MCP-style facade: TOOLS + TOOL_DISPATCH
clients/
    nvd_client.py          # NVD HTTP wrapper (rate limit + retry)
    email_client.py        # SMTP wrapper (dry-run if not configured)
storage/
    storage.py             # SQLite layer
findings.db                # runtime, gitignored
```

## Run

```bash
pip install -r requirements.txt
cp .env.example .env
# edit .env: paste OPENAI_API_KEY (required) plus optional NVD_API_KEY / SMTP
```

### Start the service

```bash
python main.py --poll-interval 60 --since-days 1 --max-items 100
# → http://127.0.0.1:5000  (Swagger UI at /docs)
```

What happens on startup:

1. **Startup batch** — `--since-days N` processes that window once before
   binding the port. Omitting it, or passing `--since-days 0`, processes
   midnight UTC to now.
2. **Background poller** — daemon thread re-runs the batch every
   `--poll-interval` seconds using the DB watermark, fetching only
   what's changed since last time.
3. **uvicorn** — serves `/classify`, `/findings`, `/health` until Ctrl+C.

Try it:

```bash
# On-demand triage of specific CVEs (full agentic flow)
curl -X POST http://127.0.0.1:5000/classify \
  -H 'Content-Type: application/json' \
  -d '{"cve_ids": ["CVE-2024-12345", "CVE-2024-67890"]}'

# Browse stored findings
curl 'http://127.0.0.1:5000/findings?severity=Critical&limit=20'

# Health (poller liveness included)
curl http://127.0.0.1:5000/health
```

The easiest way to inspect stored findings (and to try `/classify` and
`/health` interactively) is the auto-generated Swagger UI at
`http://127.0.0.1:5000/docs` — every endpoint is callable from the browser
with form fields, no `curl` needed.

### CLI flags

| flag | default | description |
|---|---|---|
| `--since-days N` | midnight UTC | Window for the startup batch (1-120). |
| `--poll-interval N` | `3600` | Seconds between background polls. |
| `--batch-size N` | `20` | CVEs per agent invocation. |
| `--page-size N` | `100` | CVEs per NVD page (1-2000). |
| `--max-items N` | unlimited | Cap total CVEs processed per run. |
| `--host` | `127.0.0.1` | HTTP bind host. |
| `--port` | `5000` | HTTP bind port. |

## Tests

Basic unit tests cover the high-value public surface — storage round-trips,
tool validation, the alert flow with a mocked SMTP, and the NVD client's
retry behaviour with mocked HTTP. No network or LLM calls in the suite.

```bash
python -m unittest discover tests -v
```

18 tests, runs in well under a second. Pure stdlib — no `pytest` or
extra dependencies.

## How it works

The control flow is **driven by the LLM** through tool calls. Three
MCP-style tools are registered in `tools/mcp_tools.py`:

- `fetch_security_data` — wraps NVD (date window or specific `cve_ids`).
- `store_findings` — persists a batch of classified CVEs in one
  transaction (one tool call, one `executemany`, one fsync).
- `send_critical_alert` — emails an alert if any of the classified CVEs
  came out as `severity='Critical'`.

The agent loop in `agent/agent.py` is the standard MCP pattern:

```
while finish_reason == "tool_calls":
    resp = client.chat.completions.create(tools=TOOLS, messages=...)
    for tc in resp.tool_calls:
        fn = TOOL_DISPATCH[tc.name]
        output = fn(**tc.arguments)
        append tool_result to messages
return final text
```

The **orchestrator** (`agent/orchestrator.py`) wraps the agent for batch
processing: paginates NVD, dedupes against the DB by
`source_last_modified`, and invokes the agent per batch (default 20
items). See `ARCHITECTURE.md` for diagrams.

## Two prompts, one agent

The same `agent.run()` runs in two modes depending on the system prompt
the caller passes:

- **`SYSTEM_INSTRUCTIONS_BATCH`** — items pre-provided in the user
  message (orchestrator-driven, used by the background poller).
- **`SYSTEM_INSTRUCTIONS_BY_ID`** — user message lists CVE IDs; the agent
  fetches them itself via `fetch_security_data(cve_ids=...)` (service's
  `/classify` endpoint).

Both prompts share a `CLASSIFICATION_RULES` block (controlled vocabulary +
severity rubric + edge cases) so the rubric lives in one place.

## The TOOL_DISPATCH pattern

`tools/mcp_tools.py` exports two parallel artifacts:

- `TOOLS` — the JSON Schemas the model sees.
- `TOOL_DISPATCH` — `{"tool_name": python_function}`, used by the agent
  loop to turn a tool call back into a real function invocation.

Adding a fourth tool means appending one entry to each — the agent loop
doesn't change. Cross-cutting concerns can be added once inside
`_invoke()` instead of in every tool — today it's where we treat a tool
returning `{ok: False}` (e.g. an SMTP send failure) as an error.

## Safety / correctness

- **`MAX_ITERATIONS`** caps the agent loop so a misbehaving model can't
  burn tokens forever.
- **Tool errors** (unknown name, bad args) are returned as `tool_result`
  with an error payload, so the model can recover instead of crashing.
- **`store_findings`** validates each row before commit; invalid rows are
  reported in `errors[]` and skipped, valid rows commit atomically.
- **`INSERT OR REPLACE`** on `cve_id` keeps re-runs idempotent.
- **Watermark dedup** (`source_last_modified`) skips the LLM call entirely
  when an incoming CVE matches what's already stored.
- **`nvd_client`** enforces NVD's rate limit proactively (sliding window)
  and retries 429/5xx with exponential backoff + jitter, honoring
  `Retry-After`.
- **`email_client`** dry-runs when SMTP isn't configured — the system
  runs end-to-end without forcing you to set up SMTP just to demo.
