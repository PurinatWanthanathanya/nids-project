from collections import deque
import queue
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from scapy.all import ARP, IP, TCP


class NIDSAnalyzer:
    """
    สมองกลตรวจจับภัยคุกคามเครือข่ายแบบ Rule-based (MITRE ATT&CK Mapped)
    ใช้เวลาจากแพ็กเก็ต (pkt.time) เป็น Logical Clock เพื่อรองรับทั้ง Live Sniffing และ PCAP Replay
    """

    def __init__(
        self,
        config: Dict[str, Any],
        event_queue: Optional[queue.Queue] = None,
    ):
        self.config = config
        self.event_queue = event_queue

        # State Management Config
        state_cfg = config.get("state_management", {})
        self.max_state_entries: int = state_cfg.get("max_state_entries", 10000)
        self.cleanup_interval: float = float(state_cfg.get("cleanup_interval_sec", 10.0))

        # Detection Configs
        det_cfg = config.get("detection", {})
        self.ps_cfg = det_cfg.get("port_scan", {})
        self.sf_cfg = det_cfg.get("syn_flood", {})
        self.arp_cfg = det_cfg.get("arp_spoofing", {})

        # Logical Clock & Metrics
        self.start_time: Optional[float] = None
        self.last_cleanup_time: float = 0.0
        self.state_overflow_count: int = 0
        self.dropped_events_count: int = 0

        # In-Memory State Tables
        # 1. Port Scan: {src_ip: {dport: last_seen_ts}}
        self.port_scan_table: Dict[str, Dict[int, float]] = {}

        # 2. SYN Flood (Per-Source): {src_ip: {"syns": deque[ts], "acks": deque[ts]}}
        self.syn_src_table: Dict[str, Dict[str, deque]] = {}

        # 3. SYN Flood (Per-Destination): {dst_ip: {"syns": deque[ts], "acks": deque[ts]}}
        self.syn_dst_table: Dict[str, Dict[str, deque]] = {}

        # 4. ARP Table: {ip: mac}
        self.arp_table: Dict[str, str] = {}
        self.trusted_hosts: Dict[str, str] = {
            k: v.lower()
            for k, v in (self.arp_cfg.get("trusted_hosts") or {}).items()
        }

    @classmethod
    def from_yaml(
        cls,
        config_path: str = "config.yaml",
        event_queue: Optional[queue.Queue] = None,
    ) -> "NIDSAnalyzer":
        with open(Path(config_path), "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        return cls(cfg, event_queue=event_queue)

    def process_packet(self, pkt) -> List[Dict[str, Any]]:
        """ประมวลผล 1 แพ็กเก็ต และคืนค่ารายการ Alert Events ที่ตรวจพบ"""
        ts = float(getattr(pkt, "time", 0.0))
        if self.start_time is None:
            self.start_time = ts
            self.last_cleanup_time = ts

        # ล้าง State ที่หมดอายุตามรอบเวลา (Periodic Eviction)
        if ts - self.last_cleanup_time >= self.cleanup_interval:
            self._cleanup_expired_states(ts)
            self.last_cleanup_time = ts

        alerts: List[Dict[str, Any]] = []

        if pkt.haslayer(ARP):
            arp_alert = self._check_arp_spoofing(pkt[ARP], ts)
            if arp_alert:
                alerts.append(arp_alert)

        elif pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            ps_alert = self._check_port_scan(ip_layer, tcp_layer, ts)
            if ps_alert:
                alerts.append(ps_alert)

            sf_alerts = self._check_syn_flood(ip_layer, tcp_layer, ts)
            alerts.extend(sf_alerts)

        # ส่งเข้า EventQueue (สำหรับ Worker Thread) แบบ Non-blocking
        if self.event_queue is not None:
            for alert in alerts:
                try:
                    self.event_queue.put_nowait(alert)
                except queue.Full:
                    self.dropped_events_count += 1

        return alerts

    def _check_arp_spoofing(self, arp_layer, ts: float) -> Optional[Dict[str, Any]]:
        """ตรวจจับ ARP Cache Poisoning (MITRE T1557.002)"""
        # ตรวจสอบเฉพาะ ARP Reply (op = 2: is-at)
        if int(arp_layer.op) != 2:
            return None

        src_ip = str(arp_layer.psrc)
        src_mac = str(arp_layer.hwsrc).lower()
        learning_duration = float(self.arp_cfg.get("learning_duration_sec", 30.0))

        # 1. เช็คกับ Trusted Hosts Whitelist ก่อนเสมอ
        if src_ip in self.trusted_hosts:
            expected_mac = self.trusted_hosts[src_ip]
            if src_mac != expected_mac:
                return self._build_alert(
                    ts=ts,
                    attack_type="ARP_SPOOFING",
                    mitre_id="T1557.002",
                    src_ip=src_ip,
                    dst_ip=str(arp_layer.pdst),
                    details=(
                        f"Trusted host {src_ip} MAC mismatch: "
                        f"expected {expected_mac}, got {src_mac}"
                    ),
                )
            return None

        # 2. ถ้าอยู่ในช่วง Learning Phase ให้บันทึก Baseline ลงตาราง
        if self.start_time is not None and (ts - self.start_time) < learning_duration:
            if src_ip in self.arp_table or len(self.arp_table) < self.max_state_entries:
                self.arp_table[src_ip] = src_mac
            else:
                self.state_overflow_count += 1
            return None

        # 3. หลังพ้น Learning Phase: ถ้าเจอ IP เดิมแต่เปลี่ยน MAC Address -> Alert!
        if src_ip in self.arp_table:
            old_mac = self.arp_table[src_ip]
            if src_mac != old_mac:
                return self._build_alert(
                    ts=ts,
                    attack_type="ARP_SPOOFING",
                    mitre_id="T1557.002",
                    src_ip=src_ip,
                    dst_ip=str(arp_layer.pdst),
                    details=f"ARP MAC changed for {src_ip}: {old_mac} -> {src_mac}",
                )
        else:
            if len(self.arp_table) < self.max_state_entries:
                self.arp_table[src_ip] = src_mac
            else:
                self.state_overflow_count += 1

        return None

    def _check_port_scan(self, ip_layer, tcp_layer, ts: float) -> Optional[Dict[str, Any]]:
        """ตรวจจับ TCP SYN Port Scan (MITRE T1046)"""
        flags = int(tcp_layer.flags)
        # ตรวจสอบเฉพาะแพ็กเก็ตที่มีเฉพาะ SYN flag (0x02) ไม่มี ACK
        if flags != 0x02:
            return None

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        dport = int(tcp_layer.dport)

        window_sec = float(self.ps_cfg.get("window_sec", 5.0))
        port_threshold = int(self.ps_cfg.get("port_threshold", 15))

        if src_ip not in self.port_scan_table:
            if len(self.port_scan_table) >= self.max_state_entries:
                self.state_overflow_count += 1
                return None
            self.port_scan_table[src_ip] = {}

        ports_map = self.port_scan_table[src_ip]

        # ลบพอร์ตที่อยู่นอก Sliding Window
        cutoff = ts - window_sec
        expired_ports = [p for p, last_ts in ports_map.items() if last_ts < cutoff]
        for p in expired_ports:
            del ports_map[p]

        ports_map[dport] = ts

        if len(ports_map) >= port_threshold:
            scanned_count = len(ports_map)
            # ล้างตารางของ IP นี้หลังแจ้งเตือน เพื่อเริ่มนับรอบหน้าใหม่
            ports_map.clear()
            return self._build_alert(
                ts=ts,
                attack_type="PORT_SCAN",
                mitre_id="T1046",
                src_ip=src_ip,
                dst_ip=dst_ip,
                details=f"SYN scan detected: {scanned_count} distinct ports within {window_sec}s",
            )

        return None

    def _check_syn_flood(self, ip_layer, tcp_layer, ts: float) -> List[Dict[str, Any]]:
        """ตรวจจับ TCP SYN Flood ทั้งแบบ Single-Source และ Random-Source (MITRE T1499.001)"""
        flags = int(tcp_layer.flags)
        is_syn_only = flags == 0x02
        is_ack_only = (flags & 0x10 != 0) and (flags & 0x02 == 0)

        if not (is_syn_only or is_ack_only):
            return []

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        window_sec = float(self.sf_cfg.get("window_sec", 1.0))
        src_threshold = int(self.sf_cfg.get("src_syn_threshold", 50))
        dst_threshold = int(self.sf_cfg.get("dst_syn_threshold", 100))
        min_unacked_ratio = float(self.sf_cfg.get("min_unacked_ratio", 0.8))
        cutoff = ts - window_sec

        alerts: List[Dict[str, Any]] = []

        # --- 1. ตรวจสอบระดับ Source IP (Per-Source SYN Flood) ---
        if src_ip not in self.syn_src_table:
            if len(self.syn_src_table) < self.max_state_entries:
                self.syn_src_table[src_ip] = {"syns": deque(), "acks": deque()}
            else:
                self.state_overflow_count += 1

        if src_ip in self.syn_src_table:
            src_entry = self.syn_src_table[src_ip]
            self._prune_deque(src_entry["syns"], cutoff)
            self._prune_deque(src_entry["acks"], cutoff)

            if is_syn_only:
                src_entry["syns"].append(ts)
            elif is_ack_only:
                src_entry["acks"].append(ts)

            syn_count = len(src_entry["syns"])
            ack_count = len(src_entry["acks"])
            if is_syn_only and syn_count >= src_threshold:
                unacked_ratio = max(0.0, (syn_count - ack_count) / syn_count)
                if unacked_ratio >= min_unacked_ratio:
                    src_entry["syns"].clear()
                    src_entry["acks"].clear()
                    alerts.append(
                        self._build_alert(
                            ts=ts,
                            attack_type="SYN_FLOOD",
                            mitre_id="T1499.001",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            details=(
                                f"Per-source SYN flood: {syn_count} SYNs in {window_sec}s "
                                f"(unacked ratio: {unacked_ratio:.2f})"
                            ),
                        )
                    )

        # --- 2. ตรวจสอบระดับ Destination IP (ป้องกัน hping3 --rand-source) ---
        if dst_ip not in self.syn_dst_table:
            if len(self.syn_dst_table) < self.max_state_entries:
                self.syn_dst_table[dst_ip] = {"syns": deque(), "acks": deque()}
            else:
                self.state_overflow_count += 1

        if dst_ip in self.syn_dst_table:
            dst_entry = self.syn_dst_table[dst_ip]
            self._prune_deque(dst_entry["syns"], cutoff)
            self._prune_deque(dst_entry["acks"], cutoff)

            if is_syn_only:
                dst_entry["syns"].append(ts)
            elif is_ack_only:
                dst_entry["acks"].append(ts)

            dst_syn_count = len(dst_entry["syns"])
            dst_ack_count = len(dst_entry["acks"])
            if is_syn_only and dst_syn_count >= dst_threshold:
                unacked_ratio = max(0.0, (dst_syn_count - dst_ack_count) / dst_syn_count)
                if unacked_ratio >= min_unacked_ratio:
                    dst_entry["syns"].clear()
                    dst_entry["acks"].clear()
                    alerts.append(
                        self._build_alert(
                            ts=ts,
                            attack_type="SYN_FLOOD",
                            mitre_id="T1499.001",
                            src_ip="MULTIPLE_SPOOFED",
                            dst_ip=dst_ip,
                            details=(
                                f"Aggregate destination SYN flood: {dst_syn_count} SYNs to {dst_ip} "
                                f"in {window_sec}s (unacked ratio: {unacked_ratio:.2f})"
                            ),
                        )
                    )

        return alerts

    @staticmethod
    def _prune_deque(dq: deque, cutoff: float) -> None:
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _cleanup_expired_states(self, ts: float) -> None:
        """กวาดล้าง Entry ที่ไม่มีความเคลื่อนไหวเกินหน้าต่างเวลา เพื่อคืนพื้นที่ RAM"""
        ps_cutoff = ts - float(self.ps_cfg.get("window_sec", 5.0))
        for src_ip in list(self.port_scan_table.keys()):
            ports_map = self.port_scan_table[src_ip]
            for port in list(ports_map.keys()):
                if ports_map[port] < ps_cutoff:
                    del ports_map[port]
            if not ports_map:
                del self.port_scan_table[src_ip]

        sf_cutoff = ts - float(self.sf_cfg.get("window_sec", 1.0))
        for table in (self.syn_src_table, self.syn_dst_table):
            for ip_key in list(table.keys()):
                entry = table[ip_key]
                self._prune_deque(entry["syns"], sf_cutoff)
                self._prune_deque(entry["acks"], sf_cutoff)
                if not entry["syns"] and not entry["acks"]:
                    del table[ip_key]

    @staticmethod
    def _build_alert(
        ts: float,
        attack_type: str,
        mitre_id: str,
        src_ip: str,
        dst_ip: str,
        details: str,
    ) -> Dict[str, Any]:
        return {
            "timestamp": ts,
            "attack_type": attack_type,
            "mitre_id": mitre_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "details": details,
        }