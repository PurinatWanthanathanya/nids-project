import argparse
from functools import wraps
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List
from flask import Flask, Response, jsonify, render_template_string, request
from werkzeug.security import check_password_hash, generate_password_hash
import yaml

app = Flask(__name__)

# โหลดรหัสผ่านจาก Environment Variable แล้วเก็บในรูปแบบ Password Hash เท่านั้น
ADMIN_USER = os.getenv("NIDS_ADMIN_USER", "admin")
ADMIN_PASS_HASH = generate_password_hash(
    os.getenv("NIDS_ADMIN_PASS", "nids2026")
)
DB_PATH = Path("data/nids_events.db")

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIDS Security Operations Dashboard</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --danger: #f43f5e;
            --warn: #f59e0b;
            --purple: #a855f7;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 24px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }
        .header h1 { font-size: 1.5rem; letter-spacing: -0.02em; }
        .badge-status {
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent);
            border: 1px solid var(--accent);
            padding: 6px 12px;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
        }
        .stat-label { color: var(--muted); font-size: 0.85rem; margin-bottom: 8px; }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .table-container {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow-x: auto;
        }
        .table-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }
        th, td {
            padding: 12px 20px;
            border-bottom: 1px solid var(--border);
        }
        th { color: var(--muted); font-weight: 600; background: rgba(15, 23, 42, 0.4); }
        tr:hover { background: rgba(255, 255, 255, 0.02); }
        .tag {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.78rem;
            font-weight: 700;
        }
        .tag-PORT_SCAN { background: rgba(245, 158, 11, 0.2); color: var(--warn); }
        .tag-SYN_FLOOD { background: rgba(244, 63, 94, 0.2); color: var(--danger); }
        .tag-ARP_SPOOFING { background: rgba(168, 85, 247, 0.2); color: var(--purple); }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
        .btn-refresh {
            background: var(--accent);
            color: #0f172a;
            border: none;
            padding: 8px 14px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ Rule-based NIDS — Security Event Dashboard</h1>
            <p style="color: var(--muted); font-size: 0.88rem; margin-top: 4px;">
                MITRE ATT&CK Mapped Network Intrusion Detection System (SQLite WAL)
            </p>
        </div>
        <div>
            <a href="/" class="btn-refresh">↻ Refresh Data</a>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">TOTAL ALERTS</div>
            <div class="stat-value">{{ stats.total }}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">PORT SCAN (T1046)</div>
            <div class="stat-value" style="color: var(--warn);">{{ stats.PORT_SCAN }}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">SYN FLOOD (T1499.001)</div>
            <div class="stat-value" style="color: var(--danger);">{{ stats.SYN_FLOOD }}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">ARP SPOOFING (T1557.002)</div>
            <div class="stat-value" style="color: var(--purple);">{{ stats.ARP_SPOOFING }}</div>
        </div>
    </div>

    <div class="table-container">
        <div class="table-header">
            <h3>Recent Security Events (Latest 100)</h3>
            <span class="badge-status">DB: {{ db_path }}</span>
        </div>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp (UTC)</th>
                    <th>Attack Type</th>
                    <th>MITRE ID</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Technical Details</th>
                </tr>
            </thead>
            <tbody>
                {% for row in alerts %}
                <tr>
                    <td class="mono">#{{ row.id }}</td>
                    <td class="mono">{{ row.iso_time }}</td>
                    <td><span class="tag tag-{{ row.attack_type }}">{{ row.attack_type }}</span></td>
                    <td class="mono">{{ row.mitre_id }}</td>
                    <td class="mono">{{ row.src_ip }}</td>
                    <td class="mono">{{ row.dst_ip }}</td>
                    <td>{{ row.details }}</td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="7" style="text-align: center; color: var(--muted); padding: 32px;">
                        No security alerts recorded yet.
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""


def requires_auth(f):
    """บังคับ HTTP Basic Authentication โดยตรวจสอบกับ Password Hash"""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if (
            not auth
            or auth.username != ADMIN_USER
            or not check_password_hash(ADMIN_PASS_HASH, auth.password)
        ):
            return Response(
                "Authentication required to access NIDS Dashboard.",
                401,
                {"WWW-Authenticate": 'Basic realm="NIDS Security Dashboard"'},
            )
        return f(*args, **kwargs)

    return decorated


def query_db() -> Dict[str, Any]:
    stats = {"total": 0, "PORT_SCAN": 0, "SYN_FLOOD": 0, "ARP_SPOOFING": 0}
    alerts: List[Dict[str, Any]] = []

    if not DB_PATH.exists():
        return {"stats": stats, "alerts": alerts}

    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        # ดึงยอดรวมแยกตามประเภทการโจมตี
        for row in conn.execute(
            "SELECT attack_type, COUNT(*) as cnt FROM alerts GROUP BY attack_type"
        ):
            atype = row["attack_type"]
            cnt = int(row["cnt"])
            stats["total"] += cnt
            if atype in stats:
                stats[atype] = cnt

        # ดึง 100 รายการล่าสุด
        cursor = conn.execute(
            """
            SELECT id, timestamp, iso_time, attack_type, mitre_id, src_ip, dst_ip, details
            FROM alerts
            ORDER BY timestamp DESC, id DESC
            LIMIT 100
            """
        )
        alerts = [dict(r) for r in cursor.fetchall()]

    return {"stats": stats, "alerts": alerts}


@app.route("/")
@requires_auth
def index():
    data = query_db()
    return render_template_string(
        DASHBOARD_HTML,
        stats=data["stats"],
        alerts=data["alerts"],
        db_path=str(DB_PATH),
    )


@app.route("/api/alerts")
@requires_auth
def api_alerts():
    return jsonify(query_db())


def main():
    global DB_PATH
    parser = argparse.ArgumentParser(description="Secured NIDS Flask Dashboard")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (use Lab IP e.g. 192.168.56.20 on Sensor VM)",
    )
    parser.add_argument("--port", type=int, default=5000, help="Port number")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            db_str = cfg.get("alerting", {}).get("sqlite_db_path")
            if db_str:
                DB_PATH = Path(db_str)

    print(f"[*] Starting Secured NIDS Dashboard on http://{args.host}:{args.port}")
    print(f"[*] Auth User: '{ADMIN_USER}' (set NIDS_ADMIN_PASS env var to change password)")
    # ปิด debug=False เสมอตามหลัก Security Hardening
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()