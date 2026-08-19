import sqlite3
from collections import Counter
from datetime import datetime

from rids_rules import (
    log_alert,
    check_https,
    check_large_packet,
    check_high_activity,
    check_icmp,
    check_udp,
    check_arp
)

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "database" / "rids.db"
def save_alert(src_ip, dst_ip, alert_type, severity, message):
    alert_conn = sqlite3.connect(DB_PATH)
    alert_cursor = alert_conn.cursor()

    alert_cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            src_ip,
            dst_ip,
            alert_type,
            severity,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        src_ip,
        dst_ip,
        alert_type,
        severity,
        message
    ))

    alert_conn.commit()
    alert_conn.close()

conn = sqlite3.connect(DB_PATH)

cursor = conn.cursor()

cursor.execute("""
SELECT id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_length
FROM packets
""")

packets = cursor.fetchall()

source_counter = Counter()

for packet in packets:
    packet_id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length = packet

    source_counter[src_ip] += 1

    result = check_https(src_ip, dst_ip, src_port, dst_port)
    if result:
        severity, message = result
        print(f"[{severity}] {message}")
        save_alert(src_ip, dst_ip, "HTTPS", severity, message)

    result = check_large_packet(src_ip, dst_ip, length)
    if result:
        severity, message = result
        print(f"[{severity}] {message}")
        log_alert(severity, message)
        save_alert(src_ip, dst_ip, "LARGE_PACKET", severity, message)

    result = check_icmp(protocol, src_ip, dst_ip)
    if result:
        severity, message = result
        print(f"[{severity}] {message}")
        save_alert(src_ip, dst_ip, "ICMP", severity, message)

    result = check_udp(protocol, src_ip, dst_ip, src_port, dst_port)
    if result:
        severity, message = result
        print(f"[{severity}] {message}")
        save_alert(src_ip, dst_ip, "UDP", severity, message)

    result = check_arp(protocol, src_ip, dst_ip)
    if result:
        severity, message = result
        print(f"[{severity}] {message}")
        save_alert(src_ip, dst_ip, "ARP", severity, message)

print("\n--- Source IP Statistics ---")

for ip, count in source_counter.items():
    print(f"{ip}: {count} packet(s)")

    result = check_high_activity(ip, count)
    if result:
        severity, message = result
        print(f"[{severity}] {message}")
        log_alert(severity, message)
        save_alert(ip, None, "HIGH_ACTIVITY", severity, message)

conn.close()
