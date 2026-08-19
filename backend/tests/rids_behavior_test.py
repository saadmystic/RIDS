import sqlite3

from rids_behavior import (
    analyze_packet,
    show_behavior,
    detect_port_scan,
    detect_destination_spread,
    calculate_behavior_risk,
    behavior_summary
)

conn = sqlite3.connect("rids.db")
cursor = conn.cursor()

cursor.execute("""
    SELECT src_ip, dst_ip, dst_port
    FROM packets
    WHERE src_ip IS NOT NULL
""")

for src_ip, dst_ip, dst_port in cursor.fetchall():
    data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port
    }

    analyze_packet(data)

conn.close()

show_behavior()
detect_port_scan()
detect_destination_spread()
calculate_behavior_risk()
behavior_summary()
