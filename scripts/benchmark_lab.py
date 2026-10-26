import argparse
import json
from pathlib import Path
import subprocess
import time
from typing import Any, Dict, List
import requests
from scapy.all import ARP, Ether, IP, TCP, send, sendp


def run_benign_session(target_ip: str, duration_sec: int = 15) -> Dict[str, Any]:
    """จำลองทราฟฟิกใช้งานปกติ (Ping + HTTP/SSH connection attempts ปกติ ไม่เกิน Threshold)"""
    print(f"[*] Running Benign Traffic Session to {target_ip} for {duration_sec}s...")
    start_ts = time.time()
    end_deadline = start_ts + duration_sec

    while time.time() < end_deadline:
        # ส่ง Ping ปกติ
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", target_ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # ส่ง SYN ปกติเพียง 2 พอร์ต (80, 443) ซึ่งต่ำกว่า Threshold (15 พอร์ต)
        for port in (80, 443):
            pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
            send(pkt, verbose=False)
        time.sleep(2.0)

    end_ts = time.time()
    return {
        "type": "BENIGN",
        "start_ts": start_ts,
        "end_ts": end_ts,
    }


def trigger_port_scan(target_ip: str) -> float:
    """ยิง TCP SYN Port Scan 20 พอร์ต (ใช้ nmap ถ้ารองรับ หรือ Scapy raw SYN)"""
    t0 = time.time()
    try:
        subprocess.run(
            ["nmap", "-sS", "-p", "1-25", "-T4", target_ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0,
            check=True,
        )
    except Exception:
        pkts = [
            IP(dst=target_ip) / TCP(sport=45000, dport=p, flags="S")
            for p in range(1, 25)
        ]
        send(pkts, verbose=False)
    return t0


def trigger_syn_flood(target_ip: str) -> float:
    """ยิง TCP SYN Flood 120 แพ็กเก็ตในเวลาสั้นๆ"""
    t0 = time.time()
    pkts = [
        IP(dst=target_ip) / TCP(sport=20000 + i, dport=80, flags="S")
        for i in range(120)
    ]
    send(pkts, verbose=False)
    return t0


def trigger_arp_spoof(target_ip: str, iface: str) -> float:
    """ยิง ARP Reply สลับ MAC Address เพื่อทริกเกอร์ ARP Spoofing"""
    # ส่ง MAC Baseline ก่อน 1 ครั้ง แล้วส่ง MAC ปลอมตามทันที
    legit = Ether(src="08:00:27:aa:bb:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc="192.168.56.99",
        hwsrc="08:00:27:aa:bb:01",
        pdst=target_ip,
    )
    sendp(legit, iface=iface, verbose=False)
    time.sleep(0.2)

    t0 = time.time()
    spoof = Ether(src="de:ad:be:ef:99:99", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc="192.168.56.99",
        hwsrc="de:ad:be:ef:99:99",
        pdst=target_ip,
    )
    sendp(spoof, iface=iface, verbose=False)
    return t0


def fetch_alerts_from_dashboard(
    target_ip: str, port: int, user: str, password: str
) -> List[Dict[str, Any]]:
    url = f"http://{target_ip}:{port}/api/alerts"
    resp = requests.get(url, auth=(user, password), timeout=5.0)
    resp.raise_for_status()
    return resp.json().get("alerts", [])


def evaluate_results(
    ground_truth: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    benign_record: Dict[str, Any],
) -> None:
    # นับ False Positives ในช่วง Benign Session
    b_start = benign_record["start_ts"]
    b_end = benign_record["end_ts"]
    false_positives = [
        a for a in alerts if b_start <= float(a["timestamp"]) <= b_end
    ]

    summary: Dict[str, Dict[str, Any]] = {
        "PORT_SCAN": {"tp": 0, "total": 0, "latencies": []},
        "SYN_FLOOD": {"tp": 0, "total": 0, "latencies": []},
        "ARP_SPOOFING": {"tp": 0, "total": 0, "latencies": []},
    }

    for gt in ground_truth:
        atype = gt["attack_type"]
        t0 = gt["start_ts"]
        t1 = gt["end_ts"] + 2.0  # เผื่อเวลาประมวลผลไม่เกิน 2 วินาที
        summary[atype]["total"] += 1

        matched = [
            a
            for a in alerts
            if a["attack_type"] == atype and (t0 - 0.5) <= float(a["timestamp"]) <= t1
        ]
        if matched:
            summary[atype]["tp"] += 1
            earliest_alert_ts = min(float(a["timestamp"]) for a in matched)
            latency = max(0.001, earliest_alert_ts - t0)
            summary[atype]["latencies"].append(latency)

    print("\n" + "=" * 65)
    print("EMPIRICAL BENCHMARK RESULTS (READY FOR README.MD)")
    print("=" * 65)
    print(
        f"Benign Traffic False Alerts : {len(false_positives)} alerts "
        f"(Duration: {b_end - b_start:.1f}s)"
    )
    print("-" * 65)
    print("| Attack Type | MITRE ID | Detection Rate | Avg Detection Latency |")
    print("| :--- | :--- | :--- | :--- |")

    mitre_map = {
        "PORT_SCAN": "T1046",
        "SYN_FLOOD": "T1499.001",
        "ARP_SPOOFING": "T1557.002",
    }
    for atype, data in summary.items():
        tp = data["tp"]
        tot = data["total"]
        lats = data["latencies"]
        avg_lat = (sum(lats) / len(lats)) if lats else 0.0
        print(
            f"| {atype} | {mitre_map[atype]} | **{tp}/{tot}** | `{avg_lat:.3f} s` |"
        )
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(
        description="Automated Live Lab Benchmark Runner & Evaluator"
    )
    parser.add_argument(
        "--target", required=True, help="Target/Sensor Ubuntu VM IP (e.g. 192.168.56.20)"
    )
    parser.add_argument(
        "--iface", default="eth0", help="Attacker network interface (e.g. eth0)"
    )
    parser.add_argument(
        "--rounds", type=int, default=5, help="Number of rounds per attack (e.g. 5 or 20)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=6.0,
        help="Wait seconds between rounds (must exceed cooldown_sec in config.yaml during benchmark)",
    )
    parser.add_argument("--port", type=int, default=5000, help="Dashboard API port")
    parser.add_argument("--user", default="admin", help="Dashboard Auth user")
    parser.add_argument("--password", default="nids2026", help="Dashboard Auth password")
    args = parser.parse_args()

    # 1. ทดสอบ Benign Traffic ก่อน
    benign_record = run_benign_session(args.target, duration_sec=10)
    time.sleep(2.0)

    # 2. วนลูปยิงทดสอบทั้ง 3 รูปแบบและบันทึก Ground Truth
    ground_truth: List[Dict[str, Any]] = []
    for r in range(1, args.rounds + 1):
        print(f"[*] Round {r}/{args.rounds}: Running PORT_SCAN...")
        t0 = trigger_port_scan(args.target)
        ground_truth.append(
            {"round": r, "attack_type": "PORT_SCAN", "start_ts": t0, "end_ts": time.time()}
        )
        time.sleep(args.interval)

        print(f"[*] Round {r}/{args.rounds}: Running SYN_FLOOD...")
        t0 = trigger_syn_flood(args.target)
        ground_truth.append(
            {"round": r, "attack_type": "SYN_FLOOD", "start_ts": t0, "end_ts": time.time()}
        )
        time.sleep(args.interval)

        print(f"[*] Round {r}/{args.rounds}: Running ARP_SPOOFING...")
        t0 = trigger_arp_spoof(args.target, args.iface)
        ground_truth.append(
            {
                "round": r,
                "attack_type": "ARP_SPOOFING",
                "start_ts": t0,
                "end_ts": time.time(),
            }
        )
        time.sleep(args.interval)

    Path("data").mkdir(exist_ok=True)
    with open("data/ground_truth.json", "w", encoding="utf-8") as f:
        json.dump(
            {"benign": benign_record, "attacks": ground_truth}, f, indent=2
        )

    # 3. ดึงผลลัพธ์จาก Dashboard API บน Sensor มาคำนวณตารางสรุปอัตโนมัติ
    try:
        alerts = fetch_alerts_from_dashboard(
            args.target, args.port, args.user, args.password
        )
        evaluate_results(ground_truth, alerts, benign_record)
    except Exception as exc:
        print(f"[WARN] Could not auto-fetch from Dashboard API: {exc}")
        print("[*] Ground truth saved to data/ground_truth.json")


if __name__ == "__main__":
    main()