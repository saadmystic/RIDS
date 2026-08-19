import sqlite3
from collections import Counter, defaultdict
from datetime import datetime

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "database" / "rids.db"

conn = sqlite3.connect(DB_PATH)

cursor = conn.cursor()

cursor.execute("""
SELECT src_ip, dst_ip, dst_port
FROM packets
WHERE src_ip IS NOT NULL
""")

packets = cursor.fetchall()

source_counter = Counter()
ports_by_source = defaultdict(set)
destinations_by_source = defaultdict(set)

for src_ip, dst_ip, dst_port in packets:
    source_counter[src_ip] += 1

    if dst_ip is not None:
        destinations_by_source[src_ip].add(dst_ip)

    if dst_port is not None:
        ports_by_source[src_ip].add(dst_port)

print("=== RIDS RISK ANALYSIS ===")

for src_ip in source_counter:
    packet_count = source_counter[src_ip]
    port_count = len(ports_by_source[src_ip])
    destination_count = len(destinations_by_source[src_ip])

    risk_score = 0

    if packet_count >= 50:
        risk_score += 3
    elif packet_count >= 10:
        risk_score += 1

    if port_count >= 10:
        risk_score += 3
    elif port_count >= 5:
        risk_score += 2

    if destination_count >= 10:
        risk_score += 3
    elif destination_count >= 5:
        risk_score += 2

    if risk_score >= 5:
        risk = "HIGH"
    elif risk_score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    print(f"\nSource: {src_ip}")
    print(f"Packets: {packet_count}")
    print(f"Unique ports: {port_count}")
    print(f"Unique destinations: {destination_count}")
    print(f"Risk Score: {risk_score}")
    print(f"Risk Level: {risk}")

    cursor.execute("""
    INSERT INTO risk_scores
    (timestamp, src_ip, packet_count, unique_ports,
     unique_destinations, risk_score, risk_level)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        src_ip,
        packet_count,
        port_count,
        destination_count,
        risk_score,
        risk
    ))

conn.commit()

print("\n=== RISK RESULTS SAVED ===")

conn.close()
