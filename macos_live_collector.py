import os
import re
import subprocess
import time
import hashlib
import requests


# ============================================================
# AI CLOUD CYBERSECURITY
# Real-Time macOS Security Telemetry Collector
# ============================================================

API_URL = "http://localhost:8000/events"

USERNAME = os.getenv("USER", "macos_user")

DEDUP_SECONDS = 10

recent_events = {}


# ============================================================
# Processes that mainly generate normal macOS background noise
# ============================================================

IGNORED_PROCESSES = {
    "kernel",
    "WindowServer",
    "runningboardd",
    "siriactionsd",
    "BackgroundShortcutRunner",
    "dasd",
    "UserEventAgent",
    "spotlightknowledged.updater",
    "corespotlightd",
    "contentlinkingd",
    "mds",
    "mdworker",
    "mdworker_shared",
    "trustd",
    "nsurlsessiond",
}


# ============================================================
# Security-focused macOS Unified Logging predicate
# ============================================================

SECURITY_PREDICATE = (
    'eventMessage CONTAINS[c] "authentication" OR '
    'eventMessage CONTAINS[c] "authenticated" OR '
    'eventMessage CONTAINS[c] "login" OR '
    'eventMessage CONTAINS[c] "logout" OR '
    'eventMessage CONTAINS[c] "authorization" OR '
    'eventMessage CONTAINS[c] "authorized" OR '
    'eventMessage CONTAINS[c] "permission" OR '
    'eventMessage CONTAINS[c] "sudo" OR '
    'eventMessage CONTAINS[c] "ssh" OR '
    'eventMessage CONTAINS[c] "firewall" OR '
    'eventMessage CONTAINS[c] "security" OR '
    'eventMessage CONTAINS[c] "denied" OR '
    'eventMessage CONTAINS[c] "authentication failed" OR '
    'eventMessage CONTAINS[c] "login failed"'
)


# ============================================================
# Extract actual process name from macOS compact log
#
# Example:
# 21:57:12.368 Df WiFiAgent[573:df8d]
#
# Result:
# WiFiAgent
# ============================================================

def extract_process(message):

    try:

        # Look for:
        # ProcessName[PID:THREAD]
        match = re.search(
            r'(?:^|\s)([A-Za-z0-9_.-]+)\[\d+:[A-Za-z0-9]+\]',
            message
        )

        if match:
            return match.group(1)

    except Exception:
        pass

    return "unknown"


# ============================================================
# Classify event type
# ============================================================

def classify_action(message):

    text = message.lower()

    if "sudo" in text or "privilege escalation" in text:
        return "PrivilegeEscalation"

    if "ssh" in text:
        return "SSHActivity"

    if "authentication failed" in text:
        return "SecurityFailure"

    if "login failed" in text:
        return "SecurityFailure"

    if "permission denied" in text:
        return "SecurityFailure"

    if "access denied" in text:
        return "SecurityFailure"

    if "authorization denied" in text:
        return "SecurityFailure"

    if "authentication" in text or "authenticated" in text:
        return "AuthenticationEvent"

    if "login" in text:
        return "LoginEvent"

    if "logout" in text:
        return "LogoutEvent"

    if "authorization" in text or "authorized" in text:
        return "AuthorizationEvent"

    if "firewall" in text:
        return "FirewallEvent"

    if "denied" in text:
        return "SecurityFailure"

    return "SecurityTelemetry"


# ============================================================
# Classify status
#
# Important:
# We only mark explicit security failures as Failed.
# Normal words such as "invalidated" or "failed" inside
# unrelated Apple diagnostics will not automatically create
# a security failure.
# ============================================================

def classify_status(message):

    text = message.lower()

    failure_patterns = [
        "authentication failed",
        "login failed",
        "permission denied",
        "access denied",
        "authorization denied",
        "security failure",
    ]

    for pattern in failure_patterns:

        if pattern in text:
            return "Failed"

    return "Success"


# ============================================================
# Determine whether event should be sent
# ============================================================

def should_send(message, process):

    # Ignore known background-noise processes.
    if process in IGNORED_PROCESSES:
        return False

    # Reject malformed process extraction.
    if process == "unknown":
        return False

    # Ignore extremely short messages.
    if len(message.strip()) < 40:
        return False

    # Create fingerprint from event content.
    fingerprint = hashlib.sha256(
        message[:500].encode(
            "utf-8",
            errors="ignore"
        )
    ).hexdigest()

    now = time.time()

    previous_time = recent_events.get(fingerprint)

    # Duplicate event within deduplication window.
    if previous_time is not None:

        if now - previous_time < DEDUP_SECONDS:
            return False

    recent_events[fingerprint] = now

    # Prevent dictionary from growing forever.
    if len(recent_events) > 1000:

        cutoff = now - DEDUP_SECONDS

        old_keys = [
            key
            for key, timestamp in recent_events.items()
            if timestamp < cutoff
        ]

        for key in old_keys:
            del recent_events[key]

    return True


# ============================================================
# Send normalized event to FastAPI
# ============================================================

def send_event(message):

    process = extract_process(message)

    if not should_send(message, process):
        return

    action = classify_action(message)

    status = classify_status(message)

    payload = {
        "user": USERNAME,

        # Local telemetry source.
        "source_ip": "127.0.0.1",

        "action": action,

        "status": status,

        # Schema-compatible representation of log size.
        "bytes_transferred": len(message),
    }

    try:

        response = requests.post(
            API_URL,
            json=payload,
            timeout=2
        )

        print(
            f"[LIVE] "
            f"{action:<22} "
            f"{status:<8} "
            f"process={process:<24} "
            f"API={response.status_code}"
        )

    except requests.RequestException as error:

        print(
            f"[ERROR] API connection failed: {error}"
        )


# ============================================================
# Main collector
# ============================================================

def main():

    command = [
        "log",
        "stream",
        "--style",
        "compact",
        "--level",
        "default",
        "--predicate",
        SECURITY_PREDICATE,
    ]

    print()
    print("=" * 72)
    print("AI CLOUD CYBERSECURITY")
    print("REAL-TIME macOS SECURITY TELEMETRY COLLECTOR")
    print("=" * 72)

    print("Telemetry source : macOS Unified Logging")
    print("API endpoint     :", API_URL)
    print("Noise filtering  : ENABLED")
    print("Deduplication    : ENABLED")
    print("Dedup window     :", DEDUP_SECONDS, "seconds")
    print("Local user       :", USERNAME)

    print("=" * 72)
    print("Waiting for security telemetry...")
    print()

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    except Exception as error:

        print(
            "[ERROR] Unable to start macOS log stream:",
            error
        )

        return

    try:

        for line in process.stdout:

            line = line.strip()

            if not line:
                continue

            send_event(line)

    except KeyboardInterrupt:

        print()
        print("Collector stopped.")

    finally:

        try:
            process.terminate()
        except Exception:
            pass


# ============================================================
# Program entry point
# ============================================================

if __name__ == "__main__":
    main()
