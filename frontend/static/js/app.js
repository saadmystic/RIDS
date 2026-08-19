// ===============================
// RIDS SYSTEM STATUS
// ===============================

function loadStatus() {

    fetch("/api/status")
        .then(response => response.json())
        .then(data => {

            console.log("RIDS API:", data);

            const statusBox = document.getElementById("rids-status");

            if (statusBox) {
                if (data.status === "online") {
                    statusBox.textContent = "RIDS ONLINE";
                } else {
                    statusBox.textContent = "RIDS OFFLINE";
                }
            }

        })
        .catch(error => {
            console.error("Status API error:", error);
        });
}

loadStatus();
setInterval(loadStatus, 2000);

// ===============================
// RIDS STATISTICS
// ===============================

function loadStats() {

    fetch("/api/stats")
        .then(response => response.json())
        .then(data => {

            const packetCount = document.getElementById("packet-count");
            if (packetCount) {
                packetCount.textContent = data.packets;
            }

            const alertCount = document.getElementById("alert-count");
            if (alertCount) {
                alertCount.textContent = data.alerts;
            }

            const highRisk = document.getElementById("high-risk-count");
            if (highRisk) {
                highRisk.textContent = data.high_risk;
            }

            const mediumRisk = document.getElementById("medium-risk-count");
            if (mediumRisk) {
                mediumRisk.textContent = data.medium_risk;
            }

            const lowRisk = document.getElementById("low-risk-count");
            if (lowRisk) {
                lowRisk.textContent = data.low_risk;
            }

            const engineStatus = document.getElementById("engine-status");
            if (engineStatus) {
                engineStatus.textContent = "ON";
            }

        })
        .catch(error => {
            console.error("Failed to load RIDS statistics:", error);
        });
}

loadStats();
setInterval(loadStats, 2000);


// ===============================
// LIVE RIDS ALERTS
// ===============================

function loadAlerts() {

    fetch("/api/alerts")
        .then(response => response.json())
        .then(alerts => {

            const container =
                document.getElementById("alerts-container");

            if (!container) {
                return;
            }

            if (alerts.length === 0) {

                container.innerHTML =
                    "<p>No alerts detected.</p>";

                return;
            }

            container.innerHTML = "";

            alerts.forEach(alert => {

                const alertItem =
                    document.createElement("div");

                alertItem.className = "alert-item";

                alertItem.innerHTML = `
                    <div class="alert-severity">
                        ${alert.severity}
                    </div>

                    <div class="alert-details">

                        <strong>
                            ${alert.message}
                        </strong>

                        <small>
                            ${alert.timestamp}
                        </small>

                    </div>
                `;

                container.appendChild(alertItem);

            });

        })
        .catch(error => {

            console.error(
                "Live alerts API error:",
                error
            );

        });
}

loadAlerts();
setInterval(loadAlerts, 2000);


// ===============================
// LIVE NETWORK TRAFFIC
// ===============================

function loadTraffic() {

    fetch("/api/traffic")
        .then(response => response.json())
        .then(data => {

            const trafficBody =
                document.getElementById("traffic-body");

            if (!trafficBody) {
                return;
            }

            trafficBody.innerHTML = "";

            data.forEach(packet => {

                const row =
                    document.createElement("tr");

                const time =
                    new Date(packet.timestamp)
                        .toLocaleTimeString();

                row.innerHTML = `
                    <td>${time}</td>

                    <td>
                        ${packet.src_ip}:${packet.src_port ?? "-"}
                    </td>

                    <td>
                        ${packet.dst_ip}:${packet.dst_port ?? "-"}
                    </td>

                    <td>
                        ${packet.protocol}
                    </td>

                    <td>
                        ${packet.packet_length} bytes
                    </td>
                `;

                trafficBody.appendChild(row);

            });

        })
        .catch(error => {

            console.error(
                "Traffic API error:",
                error
            );

        });
}

loadTraffic();
setInterval(loadTraffic, 2000);


// ===============================
// SECURITY INCIDENTS
// ===============================

function loadIncidents() {

    fetch("/api/incidents")
        .then(response => response.json())
        .then(data => {

            const incidentsBody =
                document.getElementById("incidents-body");

            if (!incidentsBody) {
                return;
            }

            incidentsBody.innerHTML = "";

            if (data.length === 0) {

                incidentsBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="loading">
                            No security incidents found.
                        </td>
                    </tr>
                `;

                return;
            }

            data.forEach(incident => {

                const row =
                    document.createElement("tr");

                row.innerHTML = `
                    <td>#${incident.id}</td>

                    <td>
                        ${incident.source_ip}
                    </td>

                    <td>
                        ${incident.alert_type}
                    </td>

                    <td>
                        <span class="severity ${incident.severity.toLowerCase()}">
                            ${incident.severity}
                        </span>
                    </td>

                    <td>
                        <span class="risk-score">
                            ${incident.risk_score}
                        </span>
                    </td>

                    <td>
                        <span class="incident-status ${incident.status.toLowerCase()}">
                            ${incident.status}
                        </span>
                    </td>
                `;

                incidentsBody.appendChild(row);

            });

        })
        .catch(error => {

            console.error(
                "Incident API error:",
                error
            );

        });
}

loadIncidents();
setInterval(loadIncidents, 3000);
async function loadAttackChains() {

    try {

        const response = await fetch("/api/attack-chains");

        if (!response.ok) {
            throw new Error("Failed to load attack chains");
        }

        const chains = await response.json();

        const container = document.getElementById(
            "attack-chains-container"
        );

        if (chains.length === 0) {
            container.innerHTML =
                "<p>No attack chains detected.</p>";
            return;
        }

        container.innerHTML = "";

        chains.forEach(chain => {

            const card = document.createElement("div");

            card.className = "alert-card";

            let chainData;

            try {
                chainData = JSON.parse(chain.chain);
            } catch (error) {
                chainData = [chain.chain];
            }

            card.innerHTML = `
                <div>
                    <strong>Attack Chain #${chain.id}</strong>
                    <p>
                        Source:
                        <strong>${chain.source_ip}</strong>
                    </p>
                    <p>
                        ${chainData.join(" → ")}
                    </p>
                </div>

                <div>
                    <strong>${chain.risk_level}</strong>
                    <p>
                        Risk Score: ${chain.risk_score}
                    </p>
                </div>
            `;

            container.appendChild(card);
        });

    } catch (error) {

        console.error(
            "Attack chain error:",
            error
        );

    }
}

loadAttackChains();

// ===============================
// RIDS RESPONSE CENTER
// ===============================

async function updateResponseStatus(responseId, status) {

    try {

        const response = await fetch(
            `/api/responses/${responseId}/status`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    status: status
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Status update failed");
        }

        loadResponseRecommendations();

    } catch (error) {

        console.error("Response status error:", error);
        alert(error.message);

    }
}


async function executeResponse(responseId) {

    try {

        const response = await fetch(
            `/api/responses/${responseId}/execute`,
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Execution failed");
        }

        console.log("Response executed:", data);

        loadResponseRecommendations();
        loadResponseExecutions();

    } catch (error) {

        console.error("Response execution error:", error);
        alert(error.message);

    }
}


// ===============================
// LOAD RESPONSE RECOMMENDATIONS
// ===============================

async function loadResponseRecommendations() {

    try {

        const chainsResponse =
            await fetch("/api/attack-chains");

        if (!chainsResponse.ok) {
            throw new Error("Failed to load attack chains");
        }

        const chains = await chainsResponse.json();

        const container =
            document.getElementById("response-container");

        if (!container) {
            return;
        }

        if (!Array.isArray(chains) || chains.length === 0) {

            container.innerHTML =
                "<p>No attack chains detected.</p>";

            return;
        }

        container.innerHTML = "";

        for (const chain of chains) {

            const response =
                await fetch(
                    `/api/attack-chains/${chain.id}/response`
                );

            if (!response.ok) {
                continue;
            }

            const data = await response.json();

            const chainHeader =
                document.createElement("div");

            chainHeader.className =
                "response-chain-header";

            chainHeader.innerHTML = `
                <strong>
                    Attack Chain #${chain.id}
                </strong>

                <span>
                    ${chain.source_ip}
                    • ${chain.risk_level}
                    • Score ${chain.risk_score}
                </span>
            `;

            container.appendChild(chainHeader);

            data.actions.forEach(item => {

                const action =
                    document.createElement("div");

                action.className =
                    "alert-item response-action";

                const statusClass =
                    item.status.toLowerCase();

                let controls = "";

                if (item.status === "RECOMMENDED") {

                    controls = `
                        <button
                            onclick="updateResponseStatus(
                                ${item.id},
                                'IN_PROGRESS'
                            )">
                            START
                        </button>
                    `;

                } else if (item.status === "IN_PROGRESS") {

                    controls = `
                        <button
                            onclick="executeResponse(
                                ${item.id}
                            )">
                            EXECUTE
                        </button>
                    `;

                } else if (item.status === "EXECUTED") {

                    controls = `
                        <span class="executed-label">
                            ✓ COMPLETED
                        </span>
                    `;

                }

                action.innerHTML = `
                    <div class="alert-severity ${statusClass}">
                        ${item.status}
                    </div>

                    <div class="alert-details">

                        <strong>
                            ${item.action}
                        </strong>

                        <small>
                            Source: ${item.source_ip}
                            |
                            Risk: ${item.risk_level}
                            |
                            Score: ${item.risk_score}
                        </small>

                        <div class="response-controls">
                            ${controls}
                        </div>

                    </div>
                `;

                container.appendChild(action);

            });

        }

    } catch (error) {

        console.error(
            "Response API error:",
            error
        );

    }
}


// ===============================
// RESPONSE EXECUTION HISTORY
// ===============================

async function loadResponseExecutions() {

    try {

        const response =
            await fetch("/api/responses/executions");

        if (!response.ok) {
            throw new Error(
                "Failed to load response executions"
            );
        }

        const executions =
            await response.json();

        const body =
            document.getElementById(
                "response-executions-body"
            );

        if (!body) {
            return;
        }

        body.innerHTML = "";

        if (
            !Array.isArray(executions) ||
            executions.length === 0
        ) {

            body.innerHTML = `
                <tr>
                    <td colspan="5" class="loading">
                        No response executions found.
                    </td>
                </tr>
            `;

            return;
        }

        executions.forEach(execution => {

            const row =
                document.createElement("tr");

            row.innerHTML = `
                <td>#${execution.id}</td>

                <td>
                    ${execution.source_ip ?? "-"}
                </td>

                <td>
                    ${execution.action ?? "-"}
                </td>

                <td>
                    <span class="incident-status executed">
                        ${execution.execution_status ?? "-"}
                    </span>
                </td>

                <td>
                    ${execution.executed_at ?? "-"}
                </td>
            `;

            body.appendChild(row);

        });

    } catch (error) {

        console.error(
            "Response execution API error:",
            error
        );

    }
}


// ===============================
// INITIALIZE RESPONSE CENTER
// ===============================

loadResponseRecommendations();
loadResponseExecutions();

setInterval(
    loadResponseRecommendations,
    3000
);

setInterval(
    loadResponseExecutions,
    3000
);
