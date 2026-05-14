"""
Background thread that runs an asyncio event loop for packet ingestion and detection.
"""
import threading
import asyncio
import queue
from src.utils.logger import setup_logger

logger = setup_logger("dashboard_realtime")

class AsyncDetectorWorker:
    def __init__(self, packet_queue: asyncio.Queue, alert_callback):
        self.packet_queue = packet_queue
        self.alert_callback = alert_callback
        self.running = True

    async def run(self):
        while self.running:
            try:
                pkt = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                # Placeholder: call your existing ai_runner detection on the packet
                # For now, just log
                logger.debug(f"Processing packet from {pkt[IP].src if hasattr(pkt, 'haslayer') else 'unknown'}")
                # Simulate alert detection
                # await self.alert_callback({"type": "simulated", "src": pkt[IP].src})
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing packet: {e}")

def start_background_detection(alert_callback):
    """Start a background thread with an asyncio event loop for packet ingestion."""
    packet_queue = asyncio.Queue(maxsize=1000)
    worker = AsyncDetectorWorker(packet_queue, alert_callback)

    def run_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(worker.run())
        # Optionally start ingestor here – for now just keep loop alive
        loop.run_forever()

    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()
    return packet_queue
