from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
LOG_PATH = BASE_DIR / "logs" / "rids_alerts.log"

def log_alert(severity, message):
    timestamp = datetime.now().isoformat()

    with open(LOG_PATH, "a") as file:
        file.write(f"{timestamp} [{severity}] {message}\n")

def check_https(src_ip, dst_ip, src_port, dst_port):
    if src_port == 443 or dst_port == 443:
        return "INFO", f"HTTPS: {src_ip} -> {dst_ip}"
    return None


def check_large_packet(src_ip, dst_ip, length):
    if length and length > 1500:
        return "HIGH", f"Large packet: {src_ip} -> {dst_ip} ({length} bytes)"
    return None


def check_high_activity(src_ip, count):
    if count >= 10:
        return "ALERT", f"High packet activity from {src_ip}: {count} packets"
    return None


def check_icmp(protocol, src_ip, dst_ip):
    if protocol == "1":
        return "INFO", f"ICMP traffic: {src_ip} -> {dst_ip}"
    return None


def check_udp(protocol, src_ip, dst_ip, src_port, dst_port):
    if protocol == "17":
        return "INFO", f"UDP traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    return None


def check_arp(protocol, src_ip, dst_ip):
    if protocol == "ARP":
        return "INFO", f"ARP traffic: {src_ip} -> {dst_ip}"
    return None
