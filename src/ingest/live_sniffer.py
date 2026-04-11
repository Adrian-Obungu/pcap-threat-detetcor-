"""
Asynchronous packet ingestion using asyncio.Queue.
Supports both live capture (AsyncSniffer) and PCAP replay.
"""
import asyncio
import sys
from scapy.all import AsyncSniffer, rdpcap
from src.utils.logger import setup_logger

logger = setup_logger("live_sniffer")

class PacketIngestor:
    def __init__(self, packet_queue: asyncio.Queue, iface=None, filter_str=None):
        self.queue = packet_queue
        self.iface = iface
        self.filter = filter_str
        self.sniffer = None
        self.replay_task = None

    def _packet_callback(self, pkt):
        """Callback for AsyncSniffer – put packet into queue."""
        try:
            self.queue.put_nowait(pkt)
        except asyncio.QueueFull:
            logger.warning("Packet queue full, dropping packet")

    async def start_live(self):
        """Start live capture using AsyncSniffer."""
        if self.iface and self.iface != 'lo':
            # Test interface availability
            try:
                test = AsyncSniffer(iface=self.iface, count=1, timeout=1)
                test.start()
                test.stop()
            except Exception as e:
                logger.error(f"Live capture not possible on {self.iface}: {e}")
                raise RuntimeError(f"Interface {self.iface} not usable")
        self.sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.filter,
            prn=self._packet_callback,
            store=False
        )
        self.sniffer.start()
        logger.info(f"Started live capture on {self.iface or 'default'} with filter '{self.filter}'")

    async def start_replay(self, pcap_path: str, speed_factor: float = 1.0):
        """Replay a PCAP file into the queue at original timing."""
        packets = rdpcap(pcap_path)
        if not packets:
            logger.warning(f"No packets in {pcap_path}")
            return
        prev_time = packets[0].time
        for pkt in packets:
            now = pkt.time
            delta = now - prev_time
            if delta > 0:
                await asyncio.sleep(delta / speed_factor)
            try:
                self.queue.put_nowait(pkt)
            except asyncio.QueueFull:
                logger.warning("Packet queue full, dropping packet during replay")
            prev_time = now
        logger.info(f"Replay of {pcap_path} completed")

    def stop(self):
        """Stop live capture."""
        if self.sniffer:
            self.sniffer.stop()
            logger.info("Live capture stopped")

async def create_ingestor(queue: asyncio.Queue, iface: str = None, filter_str: str = None, replay_pcap: str = None):
    """Factory to create and start an ingestor in either live or replay mode."""
    ingestor = PacketIngestor(queue, iface, filter_str)
    if replay_pcap:
        asyncio.create_task(ingestor.start_replay(replay_pcap))
    else:
        await ingestor.start_live()
    return ingestor
