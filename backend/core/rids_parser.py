from datetime import datetime
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "database" / "rids.db"

def save_alert(src_ip, dst_ip, alert_type, severity, message):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
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

    conn.commit()
    conn.close()

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
from scapy.all import IP, TCP, UDP, ICMP, ARP
from rids_rules import (
    log_alert,
    check_https,
    check_large_packet,
    check_icmp,
    check_udp,
    check_arp
)

def normalize_packet(p):
    data = {}
    data["timestamp"] = datetime.now().isoformat()

    if IP in p:
        data["src_ip"] = p[IP].src
        data["dst_ip"] = p[IP].dst
        data["protocol"] = p[IP].proto
        data["ttl"] = p[IP].ttl
        data["packet_length"] = len(p)

    if TCP in p:
        data["src_port"] = p[TCP].sport
        data["dst_port"] = p[TCP].dport
        data["flags"] = str(p[TCP].flags)
        data["payload_length"] = len(p[TCP].payload)

    elif UDP in p:
        data["src_port"] = p[UDP].sport
        data["dst_port"] = p[UDP].dport
        data["flags"] = None
        data["payload_length"] = len(p[UDP].payload)

    elif ICMP in p:
        data["icmp_type"] = p[ICMP].type
        data["icmp_code"] = p[ICMP].code
        data["payload_length"] = len(p[ICMP].payload)
    elif ARP in p:
        data["arp_op"] = p[ARP].op
        data["arp_src_ip"] = p[ARP].psrc
        data["arp_dst_ip"] = p[ARP].pdst
        data["arp_src_mac"] = p[ARP].hwsrc
        data["arp_dst_mac"] = p[ARP].hwdst

    return data

def save_packet(data):
    cursor.execute("""
        INSERT INTO packets
        (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_length)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("timestamp"),
        data.get("src_ip"),
        data.get("dst_ip"),
        data.get("protocol"),
        data.get("src_port"),
        data.get("dst_port"),
        data.get("packet_length")
    ))

    conn.commit()

def process_packet(packet):
    data = normalize_packet(packet)

    if not data:
        return

    save_packet(data)

    src_ip = data.get("src_ip")
    dst_ip = data.get("dst_ip")
    protocol = str(data.get("protocol"))
    src_port = data.get("src_port")
    dst_port = data.get("dst_port")
    length = data.get("packet_length")

    print(
        f"[PACKET] "
        f"{src_ip} -> {dst_ip} "
        f"({length} bytes)"
    )

    # HTTPS detection
    result = check_https(src_ip, dst_ip, src_port, dst_port)

    if result:
        severity, message = result
        print(f"[{severity}] {message}")

        if severity in ("HIGH", "ALERT"):
            save_alert(
                src_ip,
                dst_ip,
                "HTTPS",
                severity,
                message
            )

    # Large packet detection
    result = check_large_packet(src_ip, dst_ip, length)

    if result:
        severity, message = result
        print(f"[{severity}] {message}")
        log_alert(severity, message)

        if severity in ("HIGH", "ALERT"):
            save_alert(
                src_ip,
                dst_ip,
                "LARGE_PACKET",
                severity,
                message
            )

    # ICMP detection
    result = check_icmp(protocol, src_ip, dst_ip)

    if result:
        severity, message = result
        print(f"[{severity}] {message}")

        if severity in ("HIGH", "ALERT"):
            save_alert(
                src_ip,
                dst_ip,
                "ICMP",
                severity,
                message
            )

    # UDP detection
    result = check_udp(
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port
    )

    if result:
        severity, message = result
        print(f"[{severity}] {message}")

        if severity in ("HIGH", "ALERT"):
            save_alert(
                src_ip,
                dst_ip,
                "UDP",
                severity,
                message
            )

    # ARP detection
    result = check_arp(protocol, src_ip, dst_ip)

    if result:
        severity, message = result
        print(f"[{severity}] {message}")

        if severity in ("HIGH", "ALERT"):
            save_alert(
                src_ip,
                dst_ip,
                "ARP",
                severity,
                message
            )

if __name__ == "__main__":
    from scapy.all import sniff

    print("[RIDS] Starting continuous packet capture...")
    print("[RIDS] Press Ctrl+C to stop.")

    sniff(prn=process_packet, store=False)
