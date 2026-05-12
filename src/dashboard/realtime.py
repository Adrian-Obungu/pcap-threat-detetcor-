"""
Background thread that runs an asyncio event loop for packet ingestion and detection.
"""
import asyncio
import threading
import queue
import time
import sys
import os

# Add src to path for internal imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingest.live_sniffer import create_ingestor
from utils.logger import setup_logger
from detector.detector import (
    detect_arp_spoofing, 
    detect_port_scan, 
    detect_dns_tunneling,
    detect_beaconing,
    detect_user_agent_spoofing,
    detect_data_exfiltration
)
from whitelist.manager import load_whitelist

logger = setup_logger("realtime_engine")

class RealtimeEngine:
    def __init__(self):
        self.packet_queue = asyncio.Queue(maxsize=10000)
        self.alert_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.loop = None
        self.thread = None
        self.stats = {
            "packets_processed": 0,
            "alerts_count": 0,
            "start_time": time.time()
        }
        # Buffer for batch processing
        self.packet_buffer = []
        self.buffer_size = 100 # Increased for better behavioral analysis

    def start(self, iface=None, replay_pcap=None):
        """Start the engine in a background thread."""
        self.thread = threading.Thread(target=self._run_loop, args=(iface, replay_pcap), daemon=True)
        self.thread.start()

    def _run_loop(self, iface, replay_pcap):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._main_task(iface, replay_pcap))

    async def _main_task(self, iface, replay_pcap):
        # Create ingestor
        ingestor = await create_ingestor(self.packet_queue, iface=iface, replay_pcap=replay_pcap)
        
        # Start consumer
        consumer_task = asyncio.create_task(self._consume_packets())
        
        while not self.stop_event.is_set():
            await asyncio.sleep(1)
            
        ingestor.stop()
        consumer_task.cancel()

    async def _consume_packets(self):
        logger.info("Starting packet consumer task")
        while True:
            try:
                pkt = await self.packet_queue.get()
                self.packet_buffer.append(pkt)
                self.stats["packets_processed"] += 1
                
                # Process in batches for efficiency and behavioral context
                if len(self.packet_buffer) >= self.buffer_size:
                    self._run_detection(self.packet_buffer)
                    self.packet_buffer = []
                
                self.packet_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Consumer error: {e}")

    def _run_detection(self, packets):
        """Run enterprise-grade detection logic on a batch of packets."""
        try:
            # Load current whitelist for each batch
            current_whitelist = load_whitelist()
            
            # 1. ARP Spoofing
            self._process_alerts(detect_arp_spoofing(packets, whitelist=current_whitelist))
                
            # 2. Port Scan
            self._process_alerts(detect_port_scan(packets, whitelist=current_whitelist))
                
            # 3. DNS Tunneling & DGA
            self._process_alerts(detect_dns_tunneling(packets, whitelist=current_whitelist))

            # 4. Beaconing (New Phase 3)
            self._process_alerts(detect_beaconing(packets))

            # 5. UA Spoofing (New Phase 3)
            self._process_alerts(detect_user_agent_spoofing(packets))

            # 6. Data Exfiltration
            self._process_alerts(detect_data_exfiltration(packets))
                
        except Exception as e:
            logger.error(f"Error during detection: {e}", extra_data={"error": str(e)})

    def _process_alerts(self, alerts):
        """Process and push a list of alerts."""
        for alert in alerts:
            # Add correlation ID if not present
            if 'correlation_id' not in alert:
                alert['correlation_id'] = f"corr_{int(alert['time'])}"
            self._push_alert(alert)

    def _push_alert(self, alert):
        self.stats["alerts_count"] += 1
        self.alert_queue.put(alert)
        # Log with severity-based level
        severity = alert.get('severity', 'MEDIUM')
        if severity == 'CRITICAL':
            logger.error(f"CRITICAL ALERT: {alert['type']} - {alert['description']}", extra_data=alert)
        elif severity == 'HIGH':
            logger.warning(f"HIGH ALERT: {alert['type']} - {alert['description']}", extra_data=alert)
        else:
            logger.info(f"ALERT: {alert['type']} - {alert['description']}", extra_data=alert)

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join()

# Global instance for Streamlit to access
if 'engine' not in globals():
    engine = RealtimeEngine()
