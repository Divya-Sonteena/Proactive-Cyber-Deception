/* dashboard.js — Dashboard summary cards and charts */
'use strict';

const RISK_COLORS = {
  LOW:      '#10b981',
  MEDIUM:   '#f59e0b',
  HIGH:     '#f97316',
  CRITICAL: '#ef4444',
};

const ATTACK_COLORS = [
  '#3b82f6','#a855f7','#ef4444','#f59e0b','#10b981','#f97316','#6366f1','#06b6d4','#ec4899','#84cc16'
];

let riskChart = null;
let atkChart  = null;
let hourChart = null;

async function loadSummary() {
  try {
    const res = await fetch('/api/live/summary');
    const d = await res.json();

    document.getElementById('total-sessions').textContent  = d.total_sessions ?? '—';
    document.getElementById('active-sessions').textContent = d.active_sessions ?? '—';
    document.getElementById('critical-count').textContent  = d.risk_counts?.CRITICAL ?? 0;
    document.getElementById('high-count').textContent      = d.risk_counts?.HIGH ?? 0;
    document.getElementById('medium-count').textContent    = d.risk_counts?.MEDIUM ?? 0;
    document.getElementById('low-count').textContent       = d.risk_counts?.LOW ?? 0;

    // Honeypots
    const hp = d.honeypots || {};
    ['cowrie','dionaea'].forEach(src => {
      const s = hp[src] || {};
      document.getElementById(`${src}-today`).textContent = s.sessions_today ?? '—';
      document.getElementById(`${src}-last`).textContent  = s.last_event
        ? new Date(s.last_event).toLocaleString() : 'No events';
      const badge = document.getElementById(`${src}-status`);
      if (badge) {
        badge.textContent = (s.status || 'idle').toUpperCase();
        badge.className = `hp-badge hp-badge-${s.status || 'idle'}`;
      }
      // Green border glow when honeypot is actively receiving sessions
      const card = document.getElementById(`${src}-card`);
      if (card) {
        card.classList.toggle('hp-active', s.status === 'active');
      }
    });

    renderRiskChart(d.risk_counts || {});
    document.getElementById('last-updated').textContent =
      'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    console.error('Dashboard load error:', e);
  }
}

function renderRiskChart(rc) {
  const ctx = document.getElementById('risk-chart');
  if (!ctx) return;
  const labels = ['LOW','MEDIUM','HIGH','CRITICAL'];
  const data   = labels.map(l => rc[l] || 0);
  const colors = labels.map(l => RISK_COLORS[l]);

  if (riskChart) riskChart.destroy();
  riskChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#7d8ea6', boxWidth: 12, padding: 12 } },
      },
      cutout: '68%',
    }
  });
}

// ── Attack Type Breakdown chart ──────────────────────────────────────────────
async function loadAttackTypeChart() {
  const ctx = document.getElementById('attack-type-chart');
  if (!ctx) return;
  try {
    const res = await fetch('/api/live/feed?limit=200');
    const d   = await res.json();
    if (!d.rows) return;

    // Count attack types
    const counts = {};
    d.rows.forEach(r => {
      const k = r.attack_type || 'UNKNOWN';
      counts[k] = (counts[k] || 0) + 1;
    });

    // Sort by count descending
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const labels  = entries.map(([k]) => k);
    const values  = entries.map(([, v]) => v);

    if (atkChart) atkChart.destroy();
    atkChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: labels.map((_, i) => ATTACK_COLORS[i % ATTACK_COLORS.length]),
          borderRadius: 6,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#7d8ea6' }, grid: { color: 'rgba(255,255,255,0.04)' } },
          y: { ticks: { color: '#cdd5e0', font: { size: 11 } }, grid: { display: false } }
        }
      }
    });
  } catch (e) { console.error('Attack type chart error:', e); }
}

// ── Hourly Activity Trend chart ──────────────────────────────────────────────
async function loadHourlyChart() {
  const ctx = document.getElementById('hourly-trend-chart');
  if (!ctx) return;
  try {
    const res = await fetch('/api/live/trends');
    const d   = await res.json();
    const trends = d.trends || [];
    if (!trends.length) {
      ctx.parentElement.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:30px">No trend data yet — start <code>python live/runner.py</code></p>';
      return;
    }

    const labels = trends.map(t => t.hour?.slice(-5) || t.hour);
    if (hourChart) hourChart.destroy();
    hourChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: ['CRITICAL','HIGH','MEDIUM','LOW'].map(r => ({
          label: r,
          data: trends.map(t => t[r] || 0),
          backgroundColor: RISK_COLORS[r],
          borderRadius: 3,
          stack: 'risk'
        }))
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#7d8ea6', boxWidth: 10 } } },
        scales: {
          x: { stacked: true, ticks: { color: '#7d8ea6' }, grid: { color: 'rgba(255,255,255,0.04)' } },
          y: { stacked: true, ticks: { color: '#7d8ea6' }, grid: { color: 'rgba(255,255,255,0.04)' } }
        }
      }
    });
  } catch (e) { console.error('Hourly trend error:', e); }
}

// ── Init ─────────────────────────────────────────────────────────────────────
loadSummary();
loadAttackTypeChart();
loadHourlyChart();
setInterval(loadSummary, 15000);
setInterval(() => { loadAttackTypeChart(); loadHourlyChart(); }, 60000);
