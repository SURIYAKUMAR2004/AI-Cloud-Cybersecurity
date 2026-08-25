import csv
import time
from pathlib import Path

from security.live_log_stream import generate_security_event
from security.realtime_engine import process_live_event


PROJECT_ROOT = Path(__file__).resolve().parents[1]

LIVE_FILE = (
    PROJECT_ROOT
    / "data"
    / "live_events.csv"
)


FIELDS = [
    "timestamp",
    "user",
    "source_ip",
    "action",
    "status",
    "bytes_transferred"
]


def save_event(event):

    file_exists = LIVE_FILE.exists() and LIVE_FILE.stat().st_size > 0

    with open(
        LIVE_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(event)


def start_collector(interval=3):

    print(
        "\n===== LIVE EVENT COLLECTOR =====\n"
    )

    try:

        while True:

            event = generate_security_event()

            save_event(event)

            process_live_event(event)

            time.sleep(interval)

    except KeyboardInterrupt:

        print(
            "\nLive event collector stopped."
        )


if __name__ == "__main__":

    start_collector()