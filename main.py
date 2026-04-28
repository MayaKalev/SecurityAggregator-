"""CLI entry point — always runs as the FastAPI service.

  python main.py --since-days 7 --poll-interval 3600

On startup, --since-days N processes that window once before the service
binds the port. Omitting --since-days, or passing --since-days 0, processes
midnight UTC to now. The background poller then runs every --poll-interval
seconds using the DB watermark to fetch only what's changed since last time.
"""

from __future__ import annotations

# Load .env before importing modules that read env vars at import time.
from dotenv import load_dotenv

load_dotenv()

import argparse  # noqa: E402
import logging  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

import uvicorn  # noqa: E402

import service  # noqa: E402
from agent import run_batch  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)-12s  %(message)s",
    datefmt="%H:%M:%S",
)

# Quiet third-party loggers — keep errors/warnings, drop the per-request noise.
for noisy in ("httpx", "uvicorn", "uvicorn.access", "uvicorn.error", "openai"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

log = logging.getLogger("main")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AI-Driven Security Intelligence Aggregator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--since-days", type=int, default=None,
        help="Run a startup batch with this window (1-120), or 0 for "
             "midnight UTC to now. Defaults to 0.",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=3600,
        help="Seconds between poller runs.",
    )
    parser.add_argument(
        "--batch-size", type=int, default=20,
        help="Items per agent invocation.",
    )
    parser.add_argument(
        "--page-size", type=int, default=100,
        help="Items per NVD page (1-2000).",
    )
    parser.add_argument(
        "--max-items", type=int, default=None,
        help="Maximum total CVEs to process per batch run.",
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="HTTP bind host.",
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="HTTP bind port.",
    )
    args = parser.parse_args()

    # 1) Startup batch — process the requested window before binding the port.
    if not args.since_days:
        log.info("startup batch (midnight UTC → now)")
    else:
        log.info("startup batch (last %d day(s))", args.since_days)

    run_batch(
        since_days=args.since_days,
        from_watermark=False,
        batch_size=args.batch_size,
        page_size=args.page_size,
        max_items=args.max_items,
    )

    # 2) Background poller — always uses the watermark.
    def poll_forever() -> None:
        while True:
            time.sleep(args.poll_interval)
            try:
                run_batch(
                    from_watermark=True,
                    batch_size=args.batch_size,
                    page_size=args.page_size,
                    max_items=args.max_items,
                )
            except Exception as exc:
                log.error("poll failed (will retry next interval): %s", exc)

    poller = threading.Thread(target=poll_forever, daemon=True, name="poller")
    poller.start()
    service._poller_thread = poller

    # 3) Boot uvicorn — blocks until Ctrl+C.
    log.info("service ready on http://%s:%d (docs: /docs)", args.host, args.port)
    log.info("Try it out http://%s:%d/docs", args.host, args.port)
    uvicorn.run(service.app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
