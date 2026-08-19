import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parents[2]
INCIDENT_DB_PATH = BASE_DIR / "database" / "rids_incidents.db"


def initialize_response_execution_table(
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id INTEGER NOT NULL,
            chain_id INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            action TEXT NOT NULL,
            execution_status TEXT NOT NULL,
            execution_message TEXT,
            executed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    print("[RESPONSE EXECUTION TABLE] Ready")


def execute_response(
    response_id,
    db_name=INCIDENT_DB_PATH
):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            chain_id,
            source_ip,
            action,
            status
        FROM attack_responses
        WHERE id = ?
    """, (response_id,))

    row = cursor.fetchone()

    if row is None:
        conn.close()
        raise ValueError(
            f"Response ID {response_id} not found"
        )

    response_id, chain_id, source_ip, action, status = row

    execution_status = "EXECUTED"

    execution_message = (
        f"Simulated execution of {action} "
        f"for source {source_ip}"
    )

    cursor.execute("""
        INSERT INTO response_executions (
            response_id,
            chain_id,
            source_ip,
            action,
            execution_status,
            execution_message
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        response_id,
        chain_id,
        source_ip,
        action,
        execution_status,
        execution_message
    ))

    cursor.execute("""
        UPDATE attack_responses
        SET status = 'EXECUTED'
        WHERE id = ?
    """, (response_id,))

    conn.commit()
    conn.close()

    print(
        f"[RESPONSE EXECUTED] "
        f"#{response_id} | "
        f"{action} | "
        f"{source_ip}"
    )

    return {
        "response_id": response_id,
        "chain_id": chain_id,
        "source_ip": source_ip,
        "action": action,
        "execution_status": execution_status,
        "execution_message": execution_message
    }
