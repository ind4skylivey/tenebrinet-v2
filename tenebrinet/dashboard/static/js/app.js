// TenebriNET Dashboard Logic

const API_BASE = '/api/v1';
let charts = {};
let updateInterval;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initCharts();
    updateDashboard();

    // Poll for updates every 5 seconds
    updateInterval = setInterval(updateDashboard, 5000);

    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', () => {
        updateDashboard();
        const icon = document.querySelector('#refresh-btn i');
        icon.classList.add('fa-spin');
        setTimeout(() => icon.classList.remove('fa-spin'), 1000);
    });

    // Uptime counter
    startUptimeCounter();
});

function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-links li');
    const views = document.querySelectorAll('.view');

    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            // Update nav
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Update view
            const tabId = link.getAttribute('data-tab');
            views.forEach(view => view.classList.remove('active'));

            const targetView = document.getElementById(`${tabId}-view`);
            if (targetView) {
                targetView.classList.add('active');
            }
        });
    });
}

function initCharts() {
    // Attack Trends Chart
    const ctxTrends = document.getElementById('attacksChart').getContext('2d');
    charts.trends = new Chart(ctxTrends, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: '#334155' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    // Threat Distribution Chart
    const ctxThreats = document.getElementById('threatsChart').getContext('2d');
    charts.threats = new Chart(ctxThreats, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'right' }
            }
        }
    });
}

async function updateDashboard() {
    try {
        const [stats, attacks] = await Promise.all([
            fetch(`${API_BASE}/attacks/stats`).then(r => r.json()),
            fetch(`${API_BASE}/attacks?per_page=10`).then(r => r.json())
        ]);

        updateStats(stats);
        updateCharts(stats);
        updateRecentAttacks(attacks.items);
        updateTerminalFeed(attacks.items);

    } catch (error) {
        console.error('Failed to update dashboard:', error);
    }
}

function updateStats(stats) {
    // Update counters
    const sshCount = stats.attacks_by_service.ssh || 0;
    const httpCount = stats.attacks_by_service.http || 0;
    const ftpCount = stats.attacks_by_service.ftp || 0;

    // Estimate credentials (this is a rough heuristic based on threat type)
    const credCount = stats.attacks_by_threat_type.credential_attack || 0;

    animateValue('ssh-count', parseInt(document.getElementById('ssh-count').innerText), sshCount, 1000);
    animateValue('http-count', parseInt(document.getElementById('http-count').innerText), httpCount, 1000);
    animateValue('ftp-count', parseInt(document.getElementById('ftp-count').innerText), ftpCount, 1000);
    animateValue('cred-count', parseInt(document.getElementById('cred-count').innerText), credCount, 1000);
}

function updateCharts(stats) {
    // Update Threat Distribution
    const threatTypes = Object.keys(stats.attacks_by_threat_type);
    const threatCounts = Object.values(stats.attacks_by_threat_type);

    charts.threats.data.labels = threatTypes;
    charts.threats.data.datasets[0].data = threatCounts;
    charts.threats.update();

    // For trends, we'd ideally need a time-series endpoint.
    // For now, we'll simulate a live chart by pushing the current total attacks
    // In a real app, we'd fetch historical data.
    const now = new Date().toLocaleTimeString();
    const total = stats.total_attacks;

    if (charts.trends.data.labels.length > 10) {
        charts.trends.data.labels.shift();
        charts.trends.data.datasets[0].data.shift();
    }

    charts.trends.data.labels.push(now);
    charts.trends.data.datasets[0].data.push(total); // This shows cumulative, maybe diff is better?
    charts.trends.update();
}

function updateRecentAttacks(attacks) {
    const tbody = document.getElementById('recent-attacks-body');
    tbody.innerHTML = '';

    attacks.forEach(attack => {
        const row = document.createElement('tr');
        const time = new Date(attack.timestamp).toLocaleString();
        const badgeClass = `badge-${attack.service}`;

        row.innerHTML = `
            <td>${time}</td>
            <td><span class="badge ${badgeClass}">${attack.service.toUpperCase()}</span></td>
            <td>${attack.ip}</td>
            <td>${attack.threat_type || 'Unknown'}</td>
            <td>${(attack.confidence * 100).toFixed(1)}%</td>
            <td>
                <button class="btn-icon" title="View Details"><i class="fa-solid fa-eye"></i></button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function updateTerminalFeed(attacks) {
    const feed = document.getElementById('terminal-feed');
    // Only append new logs if we had a way to track them.
    // For simplicity, we'll just rebuild the last 10.
    feed.innerHTML = '';

    attacks.forEach(attack => {
        const div = document.createElement('div');
        div.className = 'log-entry';
        const time = new Date(attack.timestamp).toISOString().split('T')[1].split('.')[0];

        div.innerHTML = `
            <span class="log-time">[${time}]</span>
            <span class="log-service">${attack.service.toUpperCase()}</span>
            <span class="log-ip">${attack.ip}</span>
            <span class="log-msg">Attack detected: ${attack.threat_type || 'Suspicious activity'}</span>
        `;
        feed.appendChild(div);
    });
}

function animateValue(id, start, end, duration) {
    if (start === end) return;
    const range = end - start;
    let current = start;
    const increment = end > start ? 1 : -1;
    const stepTime = Math.abs(Math.floor(duration / range));
    const obj = document.getElementById(id);

    const timer = setInterval(function() {
        current += increment;
        obj.innerHTML = current;
        if (current == end) {
            clearInterval(timer);
        }
    }, stepTime);
}

function startUptimeCounter() {
    const startTime = Date.now();
    setInterval(() => {
        const diff = Date.now() - startTime;
        const hours = Math.floor(diff / 3600000);
        const minutes = Math.floor((diff % 3600000) / 60000);
        const seconds = Math.floor((diff % 60000) / 1000);

        document.getElementById('uptime').innerText =
            `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    }, 1000);
}
