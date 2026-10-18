import os
import time
import socket
import requests
from pathlib import Path
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

API_URL = "http://localhost:8000/events"

# Safe real-world directory to monitor
WATCH_DIR = Path.home() / "Downloads"


class SecurityEventHandler(FileSystemEventHandler):

    def send_event(self, action, path):
        try:
            size = os.path.getsize(path) if os.path.isfile(path) else 0
        except OSError:
            size = 0

        event = {
            "user": os.getenv("USER", "unknown"),
            "source_ip": socket.gethostbyname(socket.gethostname()),
            "action": action,
            "status": "Success",
            "bytes_transferred": size
        }

        try:
            response = requests.post(
                API_URL,
                json=event,
                timeout=5
            )

            print(
                f"[LIVE] {action} | "
                f"{path} | "
                f"size={size} | "
                f"API={response.status_code}"
            )

        except requests.RequestException as e:
            print(f"[ERROR] Could not send event: {e}")

    def on_created(self, event):
        if not event.is_directory:
            self.send_event("FileCreated", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.send_event("FileModified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.send_event("FileDeleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.send_event("FileMoved", event.dest_path)


if __name__ == "__main__":

    print("=" * 60)
    print("AI CLOUD CYBERSECURITY")
    print("REAL-TIME SECURITY EVENT COLLECTOR")
    print("=" * 60)

    print(f"Monitoring: {WATCH_DIR}")
    print(f"Sending events to: {API_URL}")
    print("Status: LIVE")
    print()
    print("Perform file activity inside Downloads to generate")
    print("real security events.")
    print()
    print("Press CTRL+C to stop.")
    print("=" * 60)

    WATCH_DIR.mkdir(parents=True, exist_ok=True)

    event_handler = SecurityEventHandler()

    observer = Observer()
    observer.schedule(
        event_handler,
        str(WATCH_DIR),
        recursive=True
    )

    observer.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()
