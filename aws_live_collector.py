import json
import subprocess
import time

import requests

API_URL = "http://localhost:8000/events"
REGION = "ap-south-1"
POLL_SECONDS = 10

seen_events = set()
baseline_initialized = False


def get_cloudtrail_events():
    command = [
        "aws",
        "cloudtrail",
        "lookup-events",
        "--region",
        REGION,
        "--max-results",
        "50",
        "--output",
        "json",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            print("[AWS ERROR]", result.stderr.strip())
            return []

        data = json.loads(result.stdout)
        return data.get("Events", [])

    except Exception as exc:
        print("[AWS ERROR]", exc)
        return []


def parse_cloudtrail_event(event):
    try:
        detail = json.loads(event.get("CloudTrailEvent", "{}"))
    except json.JSONDecodeError:
        detail = {}

    event_id = event.get("EventId") or detail.get("eventID")
    event_name = event.get("EventName") or detail.get("eventName")
    username = event.get("Username") or "unknown"

    source_ip = detail.get("sourceIPAddress", "unknown")

    error_code = detail.get("errorCode")
    status = "Failed" if error_code else "Success"

    return {
        "event_id": event_id,
        "timestamp": event.get("EventTime") or detail.get("eventTime"),
        "user": username,
        "source_ip": source_ip,
        "action": event_name,
        "status": status,
        "bytes_transferred": 0,
        "event_source": event.get("EventSource"),
        "error_code": error_code,
    }


def send_to_pipeline(parsed):
    payload = {
        "user": parsed["user"],
        "source_ip": parsed["source_ip"],
        "action": parsed["action"],
        "status": parsed["status"],
        "bytes_transferred": parsed["bytes_transferred"],
    }

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=10,
        )

        if response.status_code == 200:
            print(
                f"[AWS LIVE] "
                f"{parsed['action']:<25} "
                f"{parsed['status']:<8} "
                f"user={parsed['user']:<12} "
                f"ip={parsed['source_ip']} "
                f"API=200"
            )
        else:
            print(
                f"[API ERROR] HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

    except requests.RequestException as exc:
        print(f"[API ERROR] {exc}")


def main():
    global baseline_initialized

    print("=" * 70)
    print("AI CLOUD CYBERSECURITY")
    print("AWS CLOUDTRAIL REAL-TIME EVENT COLLECTOR")
    print("=" * 70)
    print(f"AWS Region       : {REGION}")
    print("CloudTrail       : Event History")
    print(f"API endpoint     : {API_URL}")
    print(f"Polling interval : {POLL_SECONDS} seconds")
    print("Duplicate filter : ENABLED")
    print("LookupEvents     : IGNORED")
    print("Startup baseline : ENABLED")
    print("=" * 70)
    print("Waiting for NEW AWS security events...\n")

    while True:
        events = get_cloudtrail_events()

        if not events:
            time.sleep(POLL_SECONDS)
            continue

        # ---------------------------------------------------------
        # FIRST POLL:
        # Treat existing CloudTrail history as a baseline.
        # Do NOT send old events to the AI pipeline.
        # ---------------------------------------------------------
        if not baseline_initialized:
            baseline_count = 0

            for event in events:
                parsed = parse_cloudtrail_event(event)

                event_id = parsed["event_id"]
                action = parsed["action"]

                if not event_id:
                    continue

                if action == "LookupEvents":
                    continue

                seen_events.add(event_id)
                baseline_count += 1

            baseline_initialized = True

            print(
                f"[BASELINE] Existing CloudTrail events marked as seen: "
                f"{baseline_count}"
            )
            print("[LIVE MODE] Now monitoring for NEW AWS events...\n")

            time.sleep(POLL_SECONDS)
            continue

        # ---------------------------------------------------------
        # SUBSEQUENT POLLS:
        # Only NEW events are sent to the AI pipeline.
        # ---------------------------------------------------------
        for event in reversed(events):
            parsed = parse_cloudtrail_event(event)

            event_id = parsed["event_id"]
            action = parsed["action"]

            if not event_id:
                continue

            if action == "LookupEvents":
                continue

            if event_id in seen_events:
                continue

            seen_events.add(event_id)

            send_to_pipeline(parsed)

        if len(seen_events) > 5000:
            seen_events.clear()

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
