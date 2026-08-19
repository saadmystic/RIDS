import sqlite3
from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parents[2]
INCIDENT_DB_PATH = BASE_DIR / "database" / "rids_incidents.db"


def initialize_attack_chain_table(
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            chain TEXT NOT NULL,
            chain_length INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            event_count INTEGER,
            unique_alert_types INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    print("[ATTACK CHAIN TABLE] Ready")


def save_attack_chain(
    chain_result,
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO attack_chains (
            source_ip,
            chain,
            chain_length,
            risk_score,
            risk_level,
            event_count,
            unique_alert_types
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        chain_result["source_ip"],
        json.dumps(chain_result["chain"]),
        chain_result["chain_length"],
        chain_result["risk_score"],
        chain_result["risk_level"],
        chain_result["event_count"],
        chain_result["unique_alert_types"]
    ))

    conn.commit()
    conn.close()

    print(
        f"[ATTACK CHAIN SAVED] "
        f"{chain_result['source_ip']} | "
        f"{chain_result['risk_level']} | "
        f"Score: {chain_result['risk_score']}"
   ) 
def get_attack_chain(
    chain_id,
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip,
            chain,
            chain_length,
            risk_score,
            risk_level,
            event_count,
            unique_alert_types,
            created_at
        FROM attack_chains
        WHERE id = ?
    """, (chain_id,))

    row = cursor.fetchone()

    conn.close()

    if row is None:
        return None

    return {
        "id": row[0],
        "source_ip": row[1],
        "chain": json.loads(row[2]),
        "chain_length": row[3],
        "risk_score": row[4],
        "risk_level": row[5],
        "event_count": row[6],
        "unique_alert_types": row[7],
        "created_at": row[8]
    }
def get_attack_chain_events(
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

    rows = cursor.fetchall()

    conn.close()

    events = []

    for row in rows:
        events.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "alert_type": row[3],
            "severity": row[4],
            "risk_score": row[5],
            "description": row[6],
            "status": row[7]
        })

    return events
def investigate_attack_chain(
    chain_id,
    db_name=INCIDENT_DB_PATH
):
    chain = get_attack_chain(chain_id, db_name)

    if chain is None:
        print(
            f"[CHAIN NOT FOUND] "
            f"Attack chain #{chain_id} does not exist"
        )
        return None

    events = get_attack_chain_events(
        chain["source_ip"],
        db_name
    )

    investigation = {
        "chain": chain,
        "events": events,
        "event_count": len(events)
    }

    print("\n=== RIDS ATTACK CHAIN INVESTIGATION ===")
    print(f"Chain ID    : {chain['id']}")
    print(f"Source IP   : {chain['source_ip']}")
    print(f"Risk level  : {chain['risk_level']}")
    print(f"Risk score  : {chain['risk_score']}")
    print(f"Chain length: {chain['chain_length']}")
    print(f"Events      : {len(events)}")

    print("\nAttack chain:")

    for index, alert_type in enumerate(
        chain["chain"],
        start=1
    ):
        print(f"{index}. {alert_type}")

    print("\nRelated events:")

    for event in events:
        print(
            f"- #{event['id']} | "
            f"{event['alert_type']} | "
            f"{event['severity']} | "
            f"Risk {event['risk_score']}"
        )

    print("=== INVESTIGATION COMPLETE ===")

    return investigation
