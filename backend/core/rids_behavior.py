from collections import defaultdict


connections = defaultdict(int)
ports = defaultdict(set)
destinations = defaultdict(set)


def analyze_packet(data):
    src_ip = data.get("src_ip")
    dst_ip = data.get("dst_ip")
    dst_port = data.get("dst_port")

    if not src_ip or not dst_ip:
        return

    connections[src_ip] += 1
    destinations[src_ip].add(dst_ip)

    if dst_port:
        ports[src_ip].add(dst_port)


def show_behavior():
    print("\n=== RIDS BEHAVIOR MONITOR ===")

    for src_ip in connections:
        print(f"\nSource: {src_ip}")
        print(f"Packets: {connections[src_ip]}")
        print(f"Unique ports: {len(ports[src_ip])}")
        print(f"Unique destinations: {len(destinations[src_ip])}")

    print("\n=== BEHAVIOR ANALYSIS COMPLETE ===")

def detect_port_scan():
    print("\n=== PORT SCAN DETECTION ===")

    for src_ip in connections:
        port_count = len(ports[src_ip])

        if port_count >= 5:
            print(
                f"[HIGH] Possible port scan: "
                f"{src_ip} contacted {port_count} unique ports"
            )
        elif port_count >= 3:
            print(
                f"[MEDIUM] Suspicious ports: "
                f"{src_ip} contacted {port_count} unique ports"
            )
        else:
            print(
                f"[LOW] {src_ip}: "
                f"{port_count} unique port(s)"
            )
def detect_destination_spread():
    print("\n=== DESTINATION SPREAD DETECTION ===")

    for src_ip in connections:
        destination_count = len(destinations[src_ip])

        if destination_count >= 5:
            print(
                f"[HIGH] Destination spread: "
                f"{src_ip} contacted {destination_count} destinations"
            )
        elif destination_count >= 3:
            print(
                f"[MEDIUM] Broad communication: "
                f"{src_ip} contacted {destination_count} destinations"
            )
        else:
            print(
                f"[LOW] {src_ip}: "
                f"{destination_count} destination(s)"
            )
def calculate_behavior_risk():
    print("\n=== BEHAVIOR RISK SCORE ===")

    for src_ip in connections:
        score = 0

        port_count = len(ports[src_ip])
        destination_count = len(destinations[src_ip])
        packet_count = connections[src_ip]

        if port_count >= 5:
            score += 3
        elif port_count >= 3:
            score += 1

        if destination_count >= 5:
            score += 3
        elif destination_count >= 3:
            score += 1

        if packet_count >= 100:
            score += 2
        elif packet_count >= 50:
            score += 1

        if score >= 5:
            level = "HIGH"
        elif score >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        print(
            f"{src_ip} | "
            f"Packets: {packet_count} | "
            f"Ports: {port_count} | "
            f"Destinations: {destination_count} | "
            f"Score: {score} | "
            f"Risk: {level}"
        )
def behavior_summary():
    print("\n=== RIDS BEHAVIOR SUMMARY ===")

    high = 0
    medium = 0
    low = 0

    for src_ip in connections:
        port_count = len(ports[src_ip])
        destination_count = len(destinations[src_ip])
        packet_count = connections[src_ip]

        score = 0

        if port_count >= 5:
            score += 3
        elif port_count >= 3:
            score += 1

        if destination_count >= 5:
            score += 3
        elif destination_count >= 3:
            score += 1

        if packet_count >= 100:
            score += 2
        elif packet_count >= 50:
            score += 1

        if score >= 5:
            high += 1
        elif score >= 3:
            medium += 1
        else:
            low += 1

    print(f"HIGH risk sources: {high}")
    print(f"MEDIUM risk sources: {medium}")
    print(f"LOW risk sources: {low}")
    print("=== SUMMARY COMPLETE ===")

from rids_alerts import create_alert, save_alert, alert_exists
def generate_behavior_alerts():
    print("\n=== GENERATING SECURITY ALERTS ===")

    for src_ip in connections:
        port_count = len(ports[src_ip])
        destination_count = len(destinations[src_ip])
        packet_count = connections[src_ip]

        risk_score, risk_level = calculate_source_risk(src_ip)

        # Port scan alert
        if port_count >= 5:
            if not alert_exists(src_ip, "PORT_SCAN"):
                alert = create_alert(
                    src_ip,
                    "PORT_SCAN",
                    "HIGH",
                    risk_score,
                    f"Possible port scanning detected: {port_count} unique ports contacted"
                )

                save_alert(alert)

                print(
                    f"[ALERT SAVED] HIGH PORT_SCAN from {src_ip} "
                    f"(Risk Score: {risk_score})"
                )

        elif port_count >= 3:
            if not alert_exists(src_ip, "PORT_SCAN"):
                alert = create_alert(
                    src_ip,
                    "PORT_SCAN",
                    "MEDIUM",
                    risk_score,
                    f"Suspicious port activity: {port_count} unique ports contacted"
                )

                save_alert(alert)

                print(
                    f"[ALERT SAVED] MEDIUM PORT_SCAN from {src_ip} "
                    f"(Risk Score: {risk_score})"
                )

        # Destination spread alert
        if destination_count >= 5:
            if not alert_exists(src_ip, "DESTINATION_SPREAD"):
                alert = create_alert(
                    src_ip,
                    "DESTINATION_SPREAD",
                    "HIGH",
                    risk_score,
                    f"Destination spread detected: {destination_count} unique destinations contacted"
                )

                save_alert(alert)

                print(
                    f"[ALERT SAVED] HIGH DESTINATION_SPREAD from {src_ip} "
                    f"(Risk Score: {risk_score})"
                )

        elif destination_count >= 3:
            if not alert_exists(src_ip, "DESTINATION_SPREAD"):
                alert = create_alert(
                    src_ip,
                    "DESTINATION_SPREAD",
                    "MEDIUM",
                    risk_score,
                    f"Broad communication: {destination_count} unique destinations contacted"
                )

                save_alert(alert)

                print(
                    f"[ALERT SAVED] MEDIUM DESTINATION_SPREAD from {src_ip} "
                    f"(Risk Score: {risk_score})"
                )

    print("=== ALERT GENERATION COMPLETE ===")

def calculate_source_risk(src_ip):
    score = 0

    port_count = len(ports[src_ip])
    destination_count = len(destinations[src_ip])
    packet_count = connections[src_ip]

    if port_count >= 5:
        score += 3
    elif port_count >= 3:
        score += 1

    if destination_count >= 5:
        score += 3
    elif destination_count >= 3:
        score += 1

    if packet_count >= 100:
        score += 2
    elif packet_count >= 50:
        score += 1

    if score >= 5:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level
