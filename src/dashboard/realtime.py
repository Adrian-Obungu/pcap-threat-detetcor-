"""
Background thread for live packet capture and detection.
"""
import threading
import queue
import time
from src.ingest.live_sniffer import sniff_live
from src.detector.ai_runner import run_hybrid_detection  # we'll adapt later

alert_queue = queue.Queue()

def capture_loop(iface=None):
    """Capture packets and push alerts into queue."""
    # For now, simulate alerts
    while True:
        # Placeholder: actually run detection on batches of packets
        time.sleep(5)
        alert_queue.put({"type": "Simulated", "description": "Test alert", "time": time.time()})

def start_background_capture(iface=None):
    thread = threading.Thread(target=capture_loop, args=(iface,), daemon=True)
    thread.start()
    return thread
