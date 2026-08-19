from datetime import datetime
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
INCIDENT_DB_PATH = BASE_DIR / "database" / "rids_incidents.db"

def create_alert(
    source_ip,
    alert_type,
    severity,
    risk_score,
    description
):
    return {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "alert_type": alert_type,
        "severity": severity,
        "risk_score": risk_score,
        "description": description
    }

def init_alert_database(db_name="INCIDENT_DB_PATH"):
    conn = sqlite3.connect(db_name)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            description TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_alert(alert, db_name="INCIDENT_DB_PATH"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incidents (
            timestamp,
            source_ip,
            alert_type,
            severity,
            risk_score,
            description,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["source_ip"],
        alert["alert_type"],
        alert["severity"],
        alert["risk_score"],
        alert["description"],
        "NEW"
    ))

    conn.commit()
    conn.close()
def update_incident_status(
    incident_id,
    new_status,
    db_name="rids_incidents.db"
):
    allowed_statuses = {
        "NEW",
        "ACKNOWLEDGED",
        "RESOLVED"
    }

    if new_status not in allowed_statuses:
        print(f"Invalid status: {new_status}")
        return False

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE incidents
        SET status = ?
        WHERE id = ?
    """, (new_status, incident_id))

    updated = cursor.rowcount > 0

    conn.commit()
    conn.close()

    if updated:
        print(
            f"[INCIDENT UPDATED] "
            f"Incident {incident_id} -> {new_status}"
        )
    else:
        print(
            f"[INCIDENT NOT FOUND] "
            f"Incident {incident_id}"
        )

    return updated

def get_incidents_by_status(status, db_name="rids_incidents.db"):
    allowed_statuses = {
        "NEW",
        "ACKNOWLEDGED",
        "RESOLVED"
    }

    if status not in allowed_statuses:
        print(f"Invalid status: {status}")
        return []

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
        WHERE status = ?
        ORDER BY id DESC
    """, (status,))

    incidents = cursor.fetchall()

    conn.close()

    return incidents
def print_status_report(db_name="rids_incidents.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT status, COUNT(*)
        FROM incidents
        GROUP BY status
    """)

    results = cursor.fetchall()

    conn.close()

    summary = {
        "NEW": 0,
        "ACKNOWLEDGED": 0,
        "RESOLVED": 0
    }

    for status, count in results:
        summary[status] = count

    print("\n=== RIDS INCIDENT STATUS REPORT ===")
    print(f"NEW incidents          : {summary['NEW']}")
    print(f"ACKNOWLEDGED incidents : {summary['ACKNOWLEDGED']}")
    print(f"RESOLVED incidents     : {summary['RESOLVED']}")
    print("=== STATUS REPORT COMPLETE ===")

def get_recent_alerts(limit=10, db_name="rids_incidents.db"):
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
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    alerts = cursor.fetchall()

    conn.close()

    return alerts

    return alerts
def get_alerts_by_severity(severity, db_name="rids_incidents.db"):
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
            description
        FROM incidents
        WHERE severity = ?
        ORDER BY id DESC
    """, (severity,))

    alerts = cursor.fetchall()

    conn.close()

    return alerts
def get_alerts_by_source(source_ip, db_name="rids_incidents.db"):
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
            description
        FROM incidents
        WHERE source_ip = ?
        ORDER BY id DESC
    """, (source_ip,))

    alerts = cursor.fetchall()

    conn.close()

    return alerts
def print_recent_alerts(limit=10, db_name="rids_incidents.db"):
    alerts = get_recent_alerts(limit, db_name)

    print("\n=== RIDS INCIDENT REPORT ===")

    if not alerts:
        print("No incidents found.")
        return

    for alert in alerts:
        (
            alert_id,
            timestamp,
            source_ip,
            alert_type,
            severity,
            risk_score,
            description,
            status
        ) = alert

        print("\n--------------------------------")
        print(f"Incident ID : {alert_id}")
        print(f"Timestamp   : {timestamp}")
        print(f"Source IP   : {source_ip}")
        print(f"Alert Type  : {alert_type}")
        print(f"Severity    : {severity}")
        print(f"Risk Score  : {risk_score}")
        print(f"Status      : {status}")
        print(f"Description : {description}")

    print("--------------------------------")
    print("=== END INCIDENT REPORT ===")

def incident_summary(db_name="rids_incidents.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM incidents
        GROUP BY severity
    """)

    results = cursor.fetchall()

    conn.close()

    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for severity, count in results:
        summary[severity] = count

    print("\n=== INCIDENT SEVERITY SUMMARY ===")
    print(f"HIGH incidents   : {summary['HIGH']}")
    print(f"MEDIUM incidents : {summary['MEDIUM']}")
    print(f"LOW incidents    : {summary['LOW']}")
    print("=== SUMMARY COMPLETE ===")
def alert_exists(source_ip, alert_type, db_name="rids_incidents.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 1
        FROM incidents
        WHERE source_ip = ?
        AND alert_type = ?
        LIMIT 1
    """, (source_ip, alert_type))

    exists = cursor.fetchone() is not None

    conn.close()

    return exists
