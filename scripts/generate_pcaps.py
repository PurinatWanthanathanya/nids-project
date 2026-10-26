from pathlib import Path
from scapy.all import ARP, Ether, IP, TCP, wrpcap

# กำหนดโฟลเดอร์ปลายทางสำหรับเก็บไฟล์ .pcap ทดสอบ
FIXTURES_DIR = Path("tests/fixtures")
BASE_TIME = 1700000000.0  # เวลาเริ่มต้นคงที่ (Deterministic logical clock)


def set_pkt_time(pkt, offset_sec: float):
    """กำหนดเวลา pkt.time ให้แพ็กเก็ตเพื่อใช้ทดสอบ Sliding Window อย่างแม่นยำ"""
    pkt.time = BASE_TIME + offset_sec
    return pkt


def generate_benign_pcap():
    """1. สร้างทราฟฟิกปกติ (ต้องไม่เกิด Alert เลย - False Positive = 0)"""
    packets = []
    t = 0.0

    # ARP ปกติจากเครื่องในวงแลน
    arp_normal = Ether(src="08:00:27:11:22:33", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc="192.168.56.20",
        hwsrc="08:00:27:11:22:33",
        pdst="192.168.56.10",
    )
    packets.append(set_pkt_time(arp_normal, t))

    # TCP 3-Way Handshake ปกติ (SYN -> SYN/ACK -> ACK) ไปยัง 3 พอร์ตมาตรฐาน (80, 443, 22)
    for port in (80, 443, 22):
        t += 1.0
        syn = (
            Ether()
            / IP(src="192.168.56.10", dst="192.168.56.20")
            / TCP(sport=50000 + port, dport=port, flags="S", seq=100)
        )
        syn_ack = (
            Ether()
            / IP(src="192.168.56.20", dst="192.168.56.10")
            / TCP(dport=50000 + port, sport=port, flags="SA", seq=200, ack=101)
        )
        ack = (
            Ether()
            / IP(src="192.168.56.10", dst="192.168.56.20")
            / TCP(sport=50000 + port, dport=port, flags="A", seq=101, ack=201)
        )
        packets.extend([
            set_pkt_time(syn, t),
            set_pkt_time(syn_ack, t + 0.05),
            set_pkt_time(ack, t + 0.10),
        ])

    wrpcap(str(FIXTURES_DIR / "benign.pcap"), packets)
    print(f"[+] Created benign.pcap ({len(packets)} packets)")


def generate_port_scan_pcap():
    """2. สร้างทราฟฟิก TCP SYN Port Scan (MITRE T1046) - ยิง 20 พอร์ตใน 2 วินาที"""
    packets = []
    # ยิง SYN ไปยังพอร์ต 1 ถึง 20 (Threshold ใน config.yaml คือ 15 พอร์ตใน 5 วินาที)
    for i, port in enumerate(range(1, 21)):
        pkt = (
            Ether()
            / IP(src="192.168.56.10", dst="192.168.56.20")
            / TCP(sport=45000, dport=port, flags="S")
        )
        packets.append(set_pkt_time(pkt, i * 0.1))

    wrpcap(str(FIXTURES_DIR / "port_scan.pcap"), packets)
    print(f"[+] Created port_scan.pcap ({len(packets)} packets)")


def generate_syn_flood_single_pcap():
    """3. สร้างทราฟฟิก SYN Flood จาก IP เดียว (MITRE T1499.001) - 60 SYNs ใน 0.6 วินาที"""
    packets = []
    # Threshold per-source คือ 50 SYNs/วินาที
    for i in range(60):
        pkt = (
            Ether()
            / IP(src="192.168.56.10", dst="192.168.56.20")
            / TCP(sport=10000 + i, dport=80, flags="S")
        )
        packets.append(set_pkt_time(pkt, i * 0.01))

    wrpcap(str(FIXTURES_DIR / "syn_flood_single.pcap"), packets)
    print(f"[+] Created syn_flood_single.pcap ({len(packets)} packets)")


def generate_syn_flood_rand_pcap():
    """4. สร้างทราฟฟิก SYN Flood แบบสุ่ม IP (--rand-source) - 120 SYNs ใน 0.6 วินาที"""
    packets = []
    # Threshold per-destination คือ 100 SYNs/วินาที
    for i in range(120):
        fake_src_ip = f"10.0.{i // 250}.{(i % 250) + 1}"
        pkt = (
            Ether()
            / IP(src=fake_src_ip, dst="192.168.56.20")
            / TCP(sport=20000 + i, dport=80, flags="S")
        )
        packets.append(set_pkt_time(pkt, i * 0.005))

    wrpcap(str(FIXTURES_DIR / "syn_flood_rand.pcap"), packets)
    print(f"[+] Created syn_flood_rand.pcap ({len(packets)} packets)")


def generate_arp_spoof_pcap():
    """5. สร้างทราฟฟิก ARP Spoofing (MITRE T1557.002) - เปลี่ยน MAC Address ของ IP เดิม"""
    packets = []

    # แพ็กเก็ตแรก (t=0.0s): บันทึก MAC จริงของ 192.168.56.20 ลงตาราง
    legit_arp = Ether(src="08:00:27:aa:bb:cc", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc="192.168.56.20",
        hwsrc="08:00:27:aa:bb:cc",
        pdst="192.168.56.10",
    )
    packets.append(set_pkt_time(legit_arp, 0.0))

    # แพ็กเก็ตที่สอง (t=5.0s): แฮกเกอร์ส่ง ARP Reply ปลอมว่า 192.168.56.20 คือ MAC ตัวเอง
    spoofed_arp = Ether(src="de:ad:be:ef:00:99", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc="192.168.56.20",
        hwsrc="de:ad:be:ef:00:99",
        pdst="192.168.56.10",
    )
    packets.append(set_pkt_time(spoofed_arp, 5.0))

    wrpcap(str(FIXTURES_DIR / "arp_spoof.pcap"), packets)
    print(f"[+] Created arp_spoof.pcap ({len(packets)} packets)")


def main():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    generate_benign_pcap()
    generate_port_scan_pcap()
    generate_syn_flood_single_pcap()
    generate_syn_flood_rand_pcap()
    generate_arp_spoof_pcap()
    print("\n[SUCCESS] สร้างไฟล์ PCAP ทั้งหมดไว้ที่ tests/fixtures/ เรียบร้อยแล้ว")


if __name__ == "__main__":
    main()