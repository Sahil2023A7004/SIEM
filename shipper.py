from queue import Queue, Full #Queue and buffer
import threading #Runs process in bg so packet sniffer never stops
import time #Controls batch timeouts between sending and receving packets and http
import requests #For sending POST req to backend SIEM ingestion API
import os #Allows pointing Network layer to any server

INGEST_URL = os.getenv("SIEM_INGEST_URL", "http://localhost:8431/api/v1/logs/ingest")
log_queue = Queue(maxsize=1000)

def enqueue_log(event):
    try:
        log_queue.put_nowait(event)
    except Full:
     print("[WARN] Queue full (1000 items). Event dropped. Check SIEM API status or increase buffer size.")

def shipper_worker():
   while True:
      event = log_queue.get()
      try:
        requests.post(INGEST_URL, json=event, timeout=3)
      except requests.exceptions.RequestException:
        print("[ERROR] Request failed. Check your SIEM API connection.")
      finally:
        log_queue.task_done()

def start_shipper():
   thread = threading.Thread(target=shipper_worker, daemon=True)
   thread.start()
    