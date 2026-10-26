import argparse
from pathlib import Path
import queue
import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple
import yaml
from scapy.all import rdpcap, sniff

# เพิ่มโฟลเดอร์หลักเข้า sys.path เพื่อให้รัน python src/sniffer.py ได้โดยตรง
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.analyzer import NIDSAnalyzer
from src.worker import AlertWorker


class NIDSEngine:
    """
    ระบบหลักที่เชื่อม 3 Threads เข้าด้วยกันผ่าน Double-Queue Pipeline:
    [Sniffer Thread] -> (PacketQueue) -> [Analyzer Thread] -> (EventQueue) -> [AlertWorker Thread]
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        net_cfg = config.get("network", {})

        self.interface: str = str(net_cfg.get("interface", "eth0"))
        self.bpf_filter: str = str(net_cfg.get("bpf_filter", "tcp or arp"))
        pkt_q_max: int = int(net_cfg.get("packet_queue_max", 2000))
        evt_q_max: int = int(net_cfg.get("event_queue_max", 500))

        self.packet_queue: queue.Queue = queue.Queue(maxsize=pkt_q_max)
        self.event_queue: queue.Queue = queue.Queue(maxsize=evt_q_max)

        self.analyzer = NIDSAnalyzer(config, event_queue=self.event_queue)
        self.worker = AlertWorker(config, event_queue=self.event_queue)

        self.total_captured: int = 0
        self.dropped_packets: int = 0
        self.stop_event = threading.Event()

    @classmethod
    def from_yaml(cls, config_path: str = "config.yaml") -> "NIDSEngine":
        with open(Path(config_path), "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        return cls(cfg)

    def _enqueue_packet(self, pkt) -> None:
        """Callback สำหรับ Scapy (Non-blocking put_nowait เท่านั้น)"""
        self.total_captured += 1
        try:
            self.packet_queue.put_nowait(pkt)
        except queue.Full:
            self.dropped_packets += 1

    def _analyzer_loop(self) -> None:
        """ดึงแพ็กเก็ตจาก PacketQueue มาตรวจจับใน Analyzer Thread"""
        while True:
            pkt = self.packet_queue.get()
            if pkt is None:
                self.packet_queue.task_done()
                break
            try:
                self.analyzer.process_packet(pkt)
            finally:
                self.packet_queue.task_done()

    def start_workers(self) -> Tuple[threading.Thread, threading.Thread]:
        analyzer_thread = threading.Thread(
            target=self._analyzer_loop, name="AnalyzerThread", daemon=True
        )
        worker_thread = threading.Thread(
            target=self.worker.run_forever, name="WorkerThread", daemon=True
        )
        analyzer_thread.start()
        worker_thread.start()
        return analyzer_thread, worker_thread

    def stop_workers(
        self,
        analyzer_thread: threading.Thread,
        worker_thread: threading.Thread,
    ) -> None:
        """ส่งสัญญาณหยุดและรอให้ Queue ประมวลผลแพ็กเก็ตที่ค้างอยู่จนหมด"""
        self.packet_queue.put(None)
        analyzer_thread.join(timeout=10.0)

        self.event_queue.put(None)
        worker_thread.join(timeout=10.0)

    def run_pcap_replay(self, pcap_path: str) -> None:
        """โหมดทดสอบ Pipeline เต็มรูปแบบจากไฟล์ .pcap (ใช้ทดสอบได้ทันทีโดยไม่ต้องเปิด Network)"""
        print(f"[*] Starting Full Pipeline PCAP Replay: {pcap_path}")
        # ปิด Learning Phase ชั่วคราวในโหมด Replay เพื่อให้จับ ARP Spoof ได้ทันที
        self.analyzer.arp_cfg["learning_duration_sec"] = 0

        analyzer_thread, worker_thread = self.start_workers()
        start_ts = time.perf_counter()

        packets = rdpcap(pcap_path)
        for pkt in packets:
            self._enqueue_packet(pkt)

        self.stop_workers(analyzer_thread, worker_thread)
        elapsed = max(0.001, time.perf_counter() - start_ts)
        self.print_summary(elapsed)

    def run_live(self, interface: Optional[str] = None) -> None:
        """โหมดดักจับแพ็กเก็ตจริงบน Network Interface (ใช้รันบน Ubuntu Sensor VM)"""
        iface = interface or self.interface
        print(
            f"[*] Starting Live NIDS on interface '{iface}' "
            f"(BPF filter: '{self.bpf_filter}')"
        )
        print("[*] Press Ctrl+C to stop...")

        analyzer_thread, worker_thread = self.start_workers()
        start_ts = time.perf_counter()

        try:
            sniff(
                iface=iface,
                filter=self.bpf_filter,
                prn=self._enqueue_packet,
                store=False,
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping NIDS Engine...")
        finally:
            self.stop_workers(analyzer_thread, worker_thread)
            elapsed = max(0.001, time.perf_counter() - start_ts)
            self.print_summary(elapsed)

    def print_summary(self, elapsed_sec: float) -> None:
        throughput = self.total_captured / elapsed_sec
        print("\n" + "=" * 55)
        print("NIDS PIPELINE EXECUTION SUMMARY")
        print("=" * 55)
        print(f"Elapsed Time          : {elapsed_sec:.3f} sec")
        print(f"Total Packets Seen    : {self.total_captured}")
        print(f"Throughput            : {throughput:.1f} pkts/sec")
        print(f"PacketQueue Drops     : {self.dropped_packets}")
        print(f"State Table Overflows : {self.analyzer.state_overflow_count}")
        print(f"Events Saved to DB    : {self.worker.saved_events_count}")
        print(f"Suppressed (Cooldown) : {self.worker.suppressed_alerts_count}")
        print(f"SQLite Database       : {self.worker.db_path}")
        print("=" * 55)


def main():
    parser = argparse.ArgumentParser(description="Rule-based NIDS Engine")
    parser.add_argument(
        "--config", default="config.yaml", help="Path to config.yaml"
    )
    parser.add_argument(
        "--iface", default=None, help="Network interface for live sniffing"
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help="Replay a .pcap file through the full 3-thread pipeline",
    )
    args = parser.parse_args()

    engine = NIDSEngine.from_yaml(args.config)
    if args.pcap:
        engine.run_pcap_replay(args.pcap)
    else:
        engine.run_live(args.iface)


if __name__ == "__main__":
    main()