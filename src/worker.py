from datetime import datetime, timezone
import os
from pathlib import Path
import queue
import sqlite3
from typing import Any, Dict, Optional, Tuple
import requests


class AlertWorker:
    """
    Worker สำหรับบันทึก Security Events ลง SQLite (WAL mode)
    และส่งแจ้งเตือนผ่าน Telegram พร้อมระบบ Cooldown ป้องกัน Alert Flood
    """

    def __init__(
        self,
        config: Dict[str, Any],
        event_queue: Optional[queue.Queue] = None,
    ):
        self.config = config
        self.event_queue = event_queue

        alert_cfg = config.get("alerting", {})
        self.cooldown_sec: float = float(alert_cfg.get("cooldown_sec", 300.0))
        self.db_path = Path(alert_cfg.get("sqlite_db_path", "data/nids_events.db"))

        tg_cfg = alert_cfg.get("telegram", {})
        self.tg_enabled: bool = bool(tg_cfg.get("enabled", False))
        self.tg_timeout: float = float(tg_cfg.get("timeout_sec", 5.0))
        self.tg_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.tg_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")

        # Cooldown Tracker: {(src_ip, attack_type): last_alert_timestamp}
        self.cooldown_table: Dict[Tuple[str, str], float] = {}
        self.suppressed_alerts_count: int = 0
        self.saved_events_count: int = 0

        self._init_db()

    def _init_db(self) -> None:
        """สร้างตาราง SQLite และเปิดใช้งานโหมด WAL เพื่อให้อ่าน/เขียนพร้อมกันได้โดยไม่ติด Lock"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    iso_time TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    mitre_id TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);"
            )
            conn.commit()

    def handle_event(self, alert: Dict[str, Any]) -> bool:
        """
        จัดการ 1 Alert Event:
        1. บันทึกลง SQLite ก่อนเสมอ (เพื่อไม่ให้ Log สูญหายแม้ Network ค้าง)
        2. ตรวจสอบ Cooldown Key (src_ip, attack_type)
        3. ส่งแจ้งเตือน Telegram (ถ้าไม่ได้ติด Cooldown)
        คืนค่า True หากส่งแจ้งเตือนออกไป, False หากติด Cooldown
        """
        ts = float(alert["timestamp"])
        src_ip = str(alert["src_ip"])
        attack_type = str(alert["attack_type"])

        # 1. เขียนลง SQLite ก่อนเสมอ
        self._write_to_sqlite(alert)
        self.saved_events_count += 1

        # 2. เช็ค Cooldown Key: (src_ip, attack_type)
        cooldown_key = (src_ip, attack_type)
        last_sent = self.cooldown_table.get(cooldown_key)
        if last_sent is not None and (ts - last_sent) < self.cooldown_sec:
            self.suppressed_alerts_count += 1
            return False

        self.cooldown_table[cooldown_key] = ts

        # 3. แสดงผลทางหน้าจอและส่ง Telegram Alert
        iso_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        print(
            f"[ALERT] {iso_str} | {attack_type} ({alert['mitre_id']}) | "
            f"{src_ip} -> {alert['dst_ip']} | {alert['details']}"
        )

        if self.tg_enabled and self.tg_token and self.tg_chat_id:
            self._send_telegram_alert(alert, iso_str)

        return True

    def _write_to_sqlite(self, alert: Dict[str, Any]) -> None:
        ts = float(alert["timestamp"])
        iso_str = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO alerts (timestamp, iso_time, attack_type, mitre_id, src_ip, dst_ip, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    iso_str,
                    str(alert["attack_type"]),
                    str(alert["mitre_id"]),
                    str(alert["src_ip"]),
                    str(alert["dst_ip"]),
                    str(alert["details"]),
                ),
            )
            conn.commit()

    def _send_telegram_alert(self, alert: Dict[str, Any], iso_str: str) -> None:
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        message = (
            f"🚨 *NIDS Security Alert*\n"
            f"*Type*: `{alert['attack_type']}` ({alert['mitre_id']})\n"
            f"*Source*: `{alert['src_ip']}`\n"
            f"*Target*: `{alert['dst_ip']}`\n"
            f"*Time*: `{iso_str}`\n"
            f"*Details*: {alert['details']}"
        )
        try:
            requests.post(
                url,
                json={
                    "chat_id": self.tg_chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                },
                timeout=self.tg_timeout,
            )
        except requests.RequestException as exc:
            print(f"[WARN] Telegram notification failed: {exc}")

    def run_forever(self) -> None:
        """รันลูปดึงข้อมูลจาก EventQueue (สำหรับรันใน Worker Thread)"""
        if self.event_queue is None:
            raise ValueError("event_queue is required for run_forever()")

        while True:
            alert = self.event_queue.get()
            if alert is None:
                self.event_queue.task_done()
                break
            try:
                self.handle_event(alert)
            finally:
                self.event_queue.task_done()