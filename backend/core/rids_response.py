import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
INCIDENT_DB_PATH = BASE_DIR / "database" / "rids_incidents.db"


def get_response_actions(risk_level):
    if risk_level == "CRITICAL":
        return [
            "ISOLATE_SOURCE",
            "BLOCK_SUSPICIOUS_TRAFFIC",
            "INVESTIGATE_RELATED_EVENTS",
            "PRESERVE_EVIDENCE",
            "ESCALATE_INCIDENT"
        ]

    elif risk_level == "HIGH":
        return [
            "MONITOR_SOURCE",
            "BLOCK_SUSPICIOUS_TRAFFIC",
            "INVESTIGATE_RELATED_EVENTS",
            "ESCALATE_INCIDENT"
        ]

    elif risk_level == "MEDIUM":
        return [
            "MONITOR_SOURCE",
            "INVESTIGATE_RELATED_EVENTS"
        ]

    return [
        "CONTINUE_MONITORING"
    ]


def generate_response(chain_id, db_name=INCIDENT_DB_PATH):

    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip,
            risk_score,
            risk_level
        FROM attack_chains
        WHERE id = ?
    """, (chain_id,))

    row = cursor.fetchone()

    conn.close()

    if row is None:
        return {
            "error": "Attack chain not found"
        }

    actions = get_response_actions(row["risk_level"])

    result = {
        "chain_id": row["id"],
        "source_ip": row["source_ip"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "actions": actions,
        "action_count": len(actions)
    }

    print("\n=== RIDS RESPONSE ENGINE ===")
    print(f"Chain ID     : {row['id']}")
    print(f"Source IP    : {row['source_ip']}")
    print(f"Risk level   : {row['risk_level']}")
    print(f"Risk score   : {row['risk_score']}")
    print("Recommended actions:")

    for index, action in enumerate(actions, 1):
        print(f"{index}. {action}")

    print("=== RESPONSE GENERATED ===")

    return result
def initialize_response_table(db_name=INCIDENT_DB_PATH):

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER,
            action TEXT NOT NULL,
            status TEXT DEFAULT 'RECOMMENDED',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    print("[RESPONSE TABLE] Ready")
def save_response(response_result, db_name=INCIDENT_DB_PATH):

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    for action in response_result["actions"]:

        cursor.execute("""
            INSERT INTO attack_responses (
                chain_id,
                source_ip,
                risk_level,
                risk_score,
                action,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            response_result["chain_id"],
            response_result["source_ip"],
            response_result["risk_level"],
            response_result["risk_score"],
            action,
            "RECOMMENDED"
        ))

    conn.commit()
    conn.close()

    print(
        f"[RESPONSE SAVED] "
        f"Chain {response_result['chain_id']} | "
        f"{response_result['action_count']} actions"
    )

def get_response(chain_id, db_name=INCIDENT_DB_PATH):

    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            chain_id,
            source_ip,
            risk_level,
            risk_score,
            action,
            status,
            created_at
        FROM attack_responses
        WHERE chain_id = ?
        ORDER BY id ASC
    """, (chain_id,))

    rows = cursor.fetchall()

    conn.close()

    responses = [dict(row) for row in rows]

    result = {
        "chain_id": chain_id,
        "action_count": len(responses),
        "actions": responses
    }

    print("\n=== RIDS RESPONSE INVESTIGATION ===")
    print(f"Chain ID    : {chain_id}")
    print(f"Actions     : {len(responses)}")

    for response in responses:
        print(
            f"- #{response['id']} | "
            f"{response['action']} | "
            f"{response['status']}"
        )

    print("=== RESPONSE INVESTIGATION COMPLETE ===")

    return result
def update_response_status(
    response_id,
    status,
    db_name=INCIDENT_DB_PATH
):

    allowed_statuses = {
        "RECOMMENDED",
        "IN_PROGRESS",
        "COMPLETED"
    }

    if status not in allowed_statuses:
        return {
            "error": "Invalid status",
            "allowed_statuses": list(allowed_statuses)
        }

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE attack_responses
        SET status = ?
        WHERE id = ?
    """, (status, response_id))

    conn.commit()

    updated = cursor.rowcount

    conn.close()

    if updated == 0:
        return {
            "error": "Response action not found",
            "response_id": response_id
        }

    result = {
        "response_id": response_id,
        "status": status
    }

    print(
        f"[RESPONSE STATUS UPDATED] "
        f"#{response_id} → {status}"
    )

    return result
