from pathlib import Path
import sys
import pytest
from scapy.all import Ether, IP, TCP, rdpcap

# เพิ่มโฟลเดอร์หลักของโปรเจกต์เข้า sys.path เพื่อให้ import src.analyzer ได้เสมอ
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.analyzer import NIDSAnalyzer

FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"


@pytest.fixture
def test_config():
    """Config สำหรับรัน Regression Test (ตั้ง learning_duration_sec เป็น 0 เพื่อทดสอบ ARP ทันที)"""
    return {
        "state_management": {
            "max_state_entries": 10000,
            "cleanup_interval_sec": 10,
        },
        "detection": {
            "port_scan": {
                "window_sec": 5,
                "port_threshold": 15,
            },
            "syn_flood": {
                "window_sec": 1,
                "src_syn_threshold": 50,
                "dst_syn_threshold": 100,
                "min_unacked_ratio": 0.8,
            },
            "arp_spoofing": {
                "learning_duration_sec": 0,
                "trusted_hosts": {
                    "192.168.56.1": "0a:00:27:00:00:00",
                },
            },
        },
    }


def replay_pcap(analyzer: NIDSAnalyzer, pcap_name: str):
    pcap_path = FIXTURES_DIR / pcap_name
    assert pcap_path.exists(), (
        f"ไม่พบไฟล์ {pcap_path} กรุณารัน 'python scripts/generate_pcaps.py' ก่อน"
    )
    packets = rdpcap(str(pcap_path))
    triggered_alerts = []
    for pkt in packets:
        alerts = analyzer.process_packet(pkt)
        triggered_alerts.extend(alerts)
    return triggered_alerts


def test_benign_traffic_zero_alerts(test_config):
    """1. ทราฟฟิกปกติ ต้องไม่เกิด Alert เลย (False Positive = 0)"""
    analyzer = NIDSAnalyzer(test_config)
    alerts = replay_pcap(analyzer, "benign.pcap")
    assert len(alerts) == 0


def test_port_scan_detection(test_config):
    """2. ทดสอบตรวจจับ TCP SYN Port Scan (MITRE T1046)"""
    analyzer = NIDSAnalyzer(test_config)
    alerts = replay_pcap(analyzer, "port_scan.pcap")
    assert len(alerts) >= 1
    assert alerts[0]["attack_type"] == "PORT_SCAN"
    assert alerts[0]["mitre_id"] == "T1046"
    assert alerts[0]["src_ip"] == "192.168.56.10"


def test_syn_flood_single_source(test_config):
    """3. ทดสอบตรวจจับ SYN Flood จาก IP เดียว (MITRE T1499.001)"""
    analyzer = NIDSAnalyzer(test_config)
    alerts = replay_pcap(analyzer, "syn_flood_single.pcap")
    assert len(alerts) >= 1
    assert alerts[0]["attack_type"] == "SYN_FLOOD"
    assert alerts[0]["mitre_id"] == "T1499.001"
    assert alerts[0]["src_ip"] == "192.168.56.10"


def test_syn_flood_random_source(test_config):
    """4. ทดสอบตรวจจับ SYN Flood แบบสุ่ม IP (--rand-source) ด้วย Aggregate Destination Counter"""
    analyzer = NIDSAnalyzer(test_config)
    alerts = replay_pcap(analyzer, "syn_flood_rand.pcap")
    assert len(alerts) >= 1
    assert alerts[0]["attack_type"] == "SYN_FLOOD"
    assert alerts[0]["mitre_id"] == "T1499.001"
    assert alerts[0]["src_ip"] == "MULTIPLE_SPOOFED"
    assert alerts[0]["dst_ip"] == "192.168.56.20"


def test_arp_spoofing_detection(test_config):
    """5. ทดสอบตรวจจับ ARP Spoofing (MITRE T1557.002)"""
    analyzer = NIDSAnalyzer(test_config)
    alerts = replay_pcap(analyzer, "arp_spoof.pcap")
    assert len(alerts) == 1
    assert alerts[0]["attack_type"] == "ARP_SPOOFING"
    assert alerts[0]["mitre_id"] == "T1557.002"
    assert alerts[0]["src_ip"] == "192.168.56.20"


def test_state_memory_ceiling(test_config):
    """6. ทดสอบการจำกัดขนาดตารางใน RAM (ป้องกัน NIDS ล่มเมื่อถูกโจมตีด้วย IP ปลอมจำนวนมาก)"""
    test_config["state_management"]["max_state_entries"] = 10
    analyzer = NIDSAnalyzer(test_config)

    for i in range(25):
        pkt = (
            Ether()
            / IP(src=f"10.99.0.{i + 1}", dst="192.168.56.20")
            / TCP(sport=40000, dport=80, flags="S")
        )
        pkt.time = 1700000000.0 + (i * 0.01)
        analyzer.process_packet(pkt)

    assert len(analyzer.port_scan_table) <= 10
    assert analyzer.state_overflow_count > 0