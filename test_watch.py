from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

class Handler(FileSystemEventHandler):
    def on_any_event(self, event):
        print("EVENT:", event.event_type, event.src_path, flush=True)

observer = Observer()
observer.schedule(Handler(), "/Users/suriya/Downloads", recursive=True)
observer.start()

print("WATCHING DOWNLOADS...", flush=True)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()
