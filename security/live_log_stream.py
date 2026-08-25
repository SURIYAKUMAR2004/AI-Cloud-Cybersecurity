import time
import random
from datetime import datetime

import pandas as pd


USERS = [
    "alice",
    "bob",
    "charlie",
    "admin"
]

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12"
]

SUSPICIOUS_IPS = [
    "45.155.205.10",
    "103.27.186.20",
    "185.220.101.5"
]

ACTIONS = [
    "Login",
    "GetObject",
    "PutObject",
    "AssumeRole",
    "CreateUser",
    "ChangePassword",
    "DeleteObject"
]


def generate_security_event():

    user = random.choice(USERS)

    # Mostly normal traffic
    if random.random() < 0.85:
        source_ip = random.choice(NORMAL_IPS)
        bytes_transferred = random.randint(
            100,
            5000
        )

    # Simulated suspicious traffic
    else:
        source_ip = random.choice(
            SUSPICIOUS_IPS
        )

        bytes_transferred = random.randint(
            50000,
            500000
        )

    action = random.choice(ACTIONS)

    status = random.choices(
        ["Success", "Failed"],
        weights=[90, 10]
    )[0]

    event = {
        "timestamp": datetime.now(),
        "user": user,
        "source_ip": source_ip,
        "action": action,
        "status": status,
        "bytes_transferred": bytes_transferred
    }

    return event


def stream_events(interval=3):

    print("\n===== LIVE SECURITY LOG STREAM =====\n")

    try:

        while True:

            event = generate_security_event()

            print(
                f"{event['timestamp']} | "
                f"{event['user']} | "
                f"{event['source_ip']} | "
                f"{event['action']} | "
                f"{event['status']} | "
                f"{event['bytes_transferred']} bytes"
            )

            time.sleep(interval)

    except KeyboardInterrupt:

        print(
            "\nLive security stream stopped."
        )


if __name__ == "__main__":

    stream_events()