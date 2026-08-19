from backend.core.rids_attack_chains import investigate_attack_chain
from flask import Flask, render_template, jsonify, request
from backend.core.rids_response_executor import execute_response
import sqlite3
from pathlib import Path
from backend.core.rids_response import get_response, update_response_status
BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "database" / "rids.db"
INCIDENT_DB_PATH = BASE_DIR / "database" / "rids_incidents.db"

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

# RIDS database
BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "database" / "rids.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "status": "online",
        "system": "RIDS",
        "monitoring": True
    })


@app.route("/api/stats")
def stats():

    conn = get_db()
    cursor = conn.cursor()

    # Total packets
    cursor.execute("SELECT COUNT(*) FROM packets")
    packet_count = cursor.fetchone()[0]

    # Total risk assessments
    cursor.execute("SELECT COUNT(*) FROM risk_scores")
    risk_count = cursor.fetchone()[0]

    # High-risk sources
    cursor.execute("""
        SELECT COUNT(DISTINCT src_ip)
        FROM risk_scores
        WHERE risk_level = 'HIGH'
    """)
    high_risk = cursor.fetchone()[0]

    # Medium-risk sources
    cursor.execute("""
        SELECT COUNT(DISTINCT src_ip)
        FROM risk_scores
        WHERE risk_level = 'MEDIUM'
    """)
    medium_risk = cursor.fetchone()[0]

    # Low-risk sources
    cursor.execute("""
        SELECT COUNT(DISTINCT src_ip)
        FROM risk_scores
        WHERE risk_level = 'LOW'
    """)
    low_risk = cursor.fetchone()[0]

    conn.close()

    # Total alerts
    log_path = BASE_DIR / "logs" / "rids_alerts.log"

    alert_count = 0

    if log_path.exists():
        with open(log_path, "r") as file:
            alert_count = sum(
                1 for line in file
                if line.strip()
            )

    return jsonify({
        "packets": packet_count,
        "alerts": alert_count,
        "risk_assessments": risk_count,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk
    })

@app.route("/api/alerts")
def alerts():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            src_ip,
            dst_ip,
            alert_type,
            severity,
            message
        FROM alerts
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()

    alerts_data = []

    for row in rows:

        alert_id, timestamp, src_ip, dst_ip, alert_type, severity, message = row

        alerts_data.append({
            "id": alert_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "alert_type": alert_type,
            "severity": severity,
            "message": message
        })

    return jsonify(alerts_data)

    return jsonify(alerts)
@app.route("/api/traffic")
def traffic():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_length
        FROM packets
        ORDER BY id DESC
        LIMIT 30
    """)

    rows = cursor.fetchall()
    conn.close()

    traffic_data = []

    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }

    for row in rows:

        packet_id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_length = row

        protocol_name = protocol_names.get(
            int(protocol),
            str(protocol)
) if protocol is not None else "UNKNOWN"

        traffic_data.append({
            "id": packet_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol_name,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_length": packet_length
        })

    return jsonify(traffic_data)

@app.route("/api/incidents")
def incidents():

    conn = sqlite3.connect(INCIDENT_DB_PATH)
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
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()

    incidents_data = []

    for row in rows:

        incident_id, timestamp, source_ip, alert_type, severity, risk_score, description, status = row

        incidents_data.append({
            "id": incident_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "alert_type": alert_type,
            "severity": severity,
            "risk_score": risk_score,
            "description": description,
            "status": status
        })

    return jsonify(incidents_data)
@app.route("/api/attack-chains")
def attack_chains():

    conn = sqlite3.connect(INCIDENT_DB_PATH)
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
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()
    conn.close()

    attack_chains_data = []

    for row in rows:

        (
            chain_id,
            source_ip,
            chain,
            chain_length,
            risk_score,
            risk_level,
            event_count,
            unique_alert_types,
            created_at
        ) = row

        attack_chains_data.append({
            "id": chain_id,
            "source_ip": source_ip,
            "chain": chain,
            "chain_length": chain_length,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "event_count": event_count,
            "unique_alert_types": unique_alert_types,
            "created_at": created_at
        })

    return jsonify(attack_chains_data)
@app.route("/api/attack-chains/<int:chain_id>")
def attack_chain_investigation(chain_id):

    investigation = investigate_attack_chain(chain_id)

    if investigation is None:
        return jsonify({
            "error": "Attack chain not found"
        }), 404

    return jsonify(investigation)

@app.route("/api/attack-chains/<int:chain_id>/response")
def attack_chain_response(chain_id):

    response = get_response(chain_id)

    if response["action_count"] == 0:
        return jsonify({
            "error": "No response actions found",
            "chain_id": chain_id
        }), 404

    return jsonify(response) 
@app.route("/api/responses/<int:response_id>/execute", methods=["POST"])
def execute_response_api(response_id):

    try:
        result = execute_response(response_id)

        return jsonify(result), 200

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 404

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500

@app.route("/api/responses/<int:response_id>/status", methods=["POST"])
def update_response_status_api(response_id):

    data = request.get_json(silent=True)

    if not data or "status" not in data:
        return jsonify({
            "error": "Status is required"
        }), 400

    result = update_response_status(
        response_id,
        data["status"]
    )

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result), 200

@app.route("/api/responses/executions")
def response_executions():

    conn = sqlite3.connect(INCIDENT_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            response_id,
            chain_id,
            source_ip,
            action,
            execution_status,
            execution_message,
            executed_at
        FROM response_executions
        ORDER BY id DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()
    conn.close()

    executions = []

    for row in rows:

        execution_id, response_id, chain_id, source_ip, action, execution_status, execution_message, executed_at = row

        executions.append({
            "id": execution_id,
            "response_id": response_id,
            "chain_id": chain_id,
            "source_ip": source_ip,
            "action": action,
            "execution_status": execution_status,
            "execution_message": execution_message,
            "executed_at": executed_at
        })

    return jsonify(executions)

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
