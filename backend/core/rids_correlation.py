from backend.detection.rids_alerts import create_alert, save_alert
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
INCIDENT_DB_PATH = BASE_DIR / "database" / "rids_incidents.db"

def get_source_incidents(
    source_ip, 
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            alert_type,
            severity,
            risk_score,
            description,
            status
        FROM incidents
        WHERE source_ip = ?
        ORDER BY id DESC
    """, (source_ip,))

    incidents = cursor.fetchall()

    conn.close()

    return incidents
def get_alert_types(source_ip, db_name=INCIDENT_DB_PATH):
    incidents = get_source_incidents(source_ip, db_name)

    alert_types = set()

    for incident in incidents:
        alert_type = incident[3]
        alert_types.add(alert_type)

    return alert_types
def calculate_correlation_score(
    source_ip,
    db_name=INCIDENT_DB_PATH
):
    incidents = get_source_incidents(source_ip, db_name)

    alert_types = set()
    score = 0

    for incident in incidents:
        alert_type = incident[3]
        severity = incident[4]

        alert_types.add(alert_type)

        if severity == "HIGH":
            score += 2
        elif severity == "MEDIUM":
            score += 1

    type_count = len(alert_types)

    if type_count >= 3:
        score += 5
    elif type_count >= 2:
        score += 3

    if score >= 8:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level
def correlation_summary(
    source_ip, 
    db_name=INCIDENT_DB_PATH
):
    incidents = get_source_incidents(source_ip, db_name)
    alert_types = get_alert_types(source_ip, db_name)

    score, level = calculate_correlation_score(
        source_ip,
        db_name
    )

    print("\n=== RIDS EVENT CORRELATION ===")
    print(f"Source IP        : {source_ip}")
    print(f"Alert types      : {len(alert_types)}")
    print(f"Correlation score: {score}")
    print(f"Correlation risk : {level}")

    print("\nDetected behaviors:")

    for alert_type in sorted(alert_types):
        print(f"- {alert_type}")

    print("\nRelated incidents:")

    for incident in incidents:
        print(
            f"- Incident #{incident[0]} | "
            f"{incident[3]} | "
            f"{incident[4]} | "
            f"{incident[7]}"
        )

    print("=== CORRELATION COMPLETE ===")
def detect_correlated_activity(
    source_ip,
    db_name=INCIDENT_DB_PATH
):
    alert_types = get_alert_types(source_ip, db_name)

    if len(alert_types) >= 2:
        print(
            f"[CORRELATED ACTIVITY] "
            f"{source_ip} shows multiple suspicious behaviors"
        )

        for alert_type in sorted(alert_types):
            print(f"  - {alert_type}")

        return True

    print(
        f"[NO CORRELATION] "
        f"{source_ip} has only one suspicious behavior"
    )

    return False
def generate_correlation_alert(
    source_ip,
    db_name=INCIDENT_DB_PATH
):
    alert_types = get_alert_types(source_ip, db_name)

    if len(alert_types) < 2:
        print(
            f"[NO CORRELATION ALERT] "
            f"{source_ip} has insufficient behaviors"
        )
        return False
    if correlation_alert_exists(source_ip, db_name):
        print(
            f"[CORRELATION EXISTS] "
            f"Alert already exists for {source_ip}"
        )
        return False

    score, level = calculate_correlation_score(
        source_ip,
        db_name
    )

    behavior_text = ", ".join(sorted(alert_types))

    alert = create_alert(
        source_ip,
        "CORRELATED_ACTIVITY",
        level,
        score,
        f"Multiple suspicious behaviors detected: {behavior_text}"
    )

    save_alert(alert)

    print(
        f"[CORRELATION ALERT SAVED] "
        f"{source_ip} | "
        f"{level} | "
        f"Risk Score: {score}"
    )

    return True
def correlation_alert_exists(
    source_ip,
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM incidents
        WHERE source_ip = ?
        AND alert_type = 'CORRELATED_ACTIVITY'
        LIMIT 1
    """, (source_ip,))

    result = cursor.fetchone()

    conn.close()

    return result is not None
def get_attack_timeline(
    source_ip,
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            alert_type,
            severity,
            risk_score,
            description,
            status
        FROM incidents
        WHERE source_ip = ?
        ORDER BY timestamp ASC
    """, (source_ip,))

    incidents = cursor.fetchall()

    conn.close()

    timeline = []

    for incident in incidents:
        timeline.append({
            "id": incident[0],
            "timestamp": incident[1],
            "source_ip": incident[2],
            "alert_type": incident[3],
            "severity": incident[4],
            "risk_score": incident[5],
            "description": incident[6],
            "status": incident[7]
        })

    return timeline
def detect_attack_chain(
    source_ip,
    db_name=INCIDENT_DB_PATH
):
    timeline = get_attack_timeline(source_ip, db_name)

    if len(timeline) < 2:
        print(
            f"[NO ATTACK CHAIN] "
            f"{source_ip} has insufficient events"
        )
        return None

    attack_types = [
        event["alert_type"]
        for event in timeline
    ]

    chain = []

    if "PORT_SCAN" in attack_types:
        chain.append("PORT_SCAN")

    if "DESTINATION_SPREAD" in attack_types:
        chain.append("DESTINATION_SPREAD")

    if "CORRELATED_ACTIVITY" in attack_types:
        chain.append("CORRELATED_ACTIVITY")

    if len(chain) < 2:
        print(
            f"[NO ATTACK CHAIN] "
            f"{source_ip} has no recognized attack sequence"
        )
        return None

    if len(chain) >= 3:
        risk_level = "HIGH"
    else:
        risk_level = "MEDIUM"

    result = {
        "source_ip": source_ip,
        "chain": chain,
        "chain_length": len(chain),
        "risk_level": risk_level,
        "events": timeline
    }

    print("\n=== RIDS ATTACK CHAIN ===")
    print(f"Source IP   : {source_ip}")
    print(f"Chain       : {' -> '.join(chain)}")
    print(f"Chain length: {len(chain)}")
    print(f"Risk level  : {risk_level}")
    print("=== ATTACK CHAIN COMPLETE ===")

    return result
def calculate_attack_chain_risk(
    source_ip,
    db_name=INCIDENT_DB_PATH
):
    timeline = get_attack_timeline(source_ip, db_name)

    if len(timeline) < 2:
        return {
            "source_ip": source_ip,
            "score": 0,
            "risk_level": "LOW",
            "reason": "Insufficient events"
        }

    score = 0

    for event in timeline:
        severity = event["severity"]
        risk_score = event["risk_score"]

        if severity == "HIGH":
            score += 3
        elif severity == "MEDIUM":
            score += 2
        elif severity == "LOW":
            score += 1

        score += risk_score

    unique_types = set(
        event["alert_type"]
        for event in timeline
    )

    if len(unique_types) >= 3:
        score += 5
    elif len(unique_types) >= 2:
        score += 3

    if score >= 15:
        risk_level = "CRITICAL"
    elif score >= 10:
        risk_level = "HIGH"
    elif score >= 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    result = {
        "source_ip": source_ip,
        "chain": [
            event["alert_type"]
            for event in timeline
        ],
        "chain_length": len(timeline),
        "risk_score": score,
        "risk_level": risk_level,
        "event_count": len(timeline),
        "unique_alert_types": len(unique_types)
    }

    print("\n=== RIDS ATTACK CHAIN RISK ===")
    print(f"Source IP          : {source_ip}")
    print(f"Event count        : {len(timeline)}")
    print(f"Unique alert types : {len(unique_types)}")
    print(f"Attack-chain score : {score}")
    print(f"Risk level         : {risk_level}")
    print("=== RISK CALCULATION COMPLETE ===")

    return result
