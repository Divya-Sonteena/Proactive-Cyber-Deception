/* live_monitor.js — Live monitoring table: WebSocket + polling fallback, date grouping */
'use strict';

const RISK_COLORS = { LOW: '#10b981', MEDIUM: '#f59e0b', HIGH: '#f97316', CRITICAL: '#ef4444' };

let socket    = null;
let pollTimer = null;
let lastSince = '';
let page      = 1;
const limit   = 50;

// Per-date session counts for the date separator badges
const dateCounts = {};

// ── WS status indicator ─────────────────────────────────────────────────────
function setWsStatus(state, msg) {
    const feed = document.getElementById('feed-status');
    if (feed) feed.textContent = msg;
}

// ── Date helpers ────────────────────────────────────────────────────────────
function toDateLabel(isoStr) {
    if (!isoStr) return 'Unknown';
    const d = new Date(isoStr);
    const today    = new Date();
    const yesterday = new Date(); yesterday.setDate(today.getDate() - 1);
    const ds = d.toDateString();
    if (ds === today.toDateString())     return 'Today';
    if (ds === yesterday.toDateString()) return 'Yesterday';
    return d.toLocaleDateString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
}

function toDateKey(isoStr) {
    if (!isoStr) return 'unknown';
    return new Date(isoStr).toISOString().slice(0, 10);
}

// ── Build a date separator row ──────────────────────────────────────────────
function buildDateSeparator(label, dateKey) {
    const count = dateCounts[dateKey] || '';
    return `<tr class="date-separator" data-date="${dateKey}">
        <td colspan="10">
            <span class="date-separator-label">📅 ${label}</span>
            ${count ? `<span class="date-separator-count">${count} sessions</span>` : ''}
        </td>
    </tr>`;
}

// ── Build a table row ───────────────────────────────────────────────────────
function buildRow(r) {
    const riskColor = RISK_COLORS[r.risk_level] || '#7d8ea6';
    const riskBadge = `<span class="risk-badge risk-${r.risk_level}" style="color:${riskColor}">${r.risk_level}</span>`;
    const ts = r.inferred_at ? new Date(r.inferred_at).toLocaleTimeString() : '—';
    const srcBadge = r.source === 'cowrie'
        ? '<span style="color:#a78bfa">Cowrie</span>'
        : '<span style="color:#34d399">Dionaea</span>';

    // Severity score cell
    const sev = r.combined_severity;
    let sevColor = '#7d8ea6';
    if (sev != null) {
        if (sev >= 2.0) sevColor = '#ef4444';
        else if (sev >= 1.2) sevColor = '#f97316';
        else if (sev >= 0.5) sevColor = '#f59e0b';
        else sevColor = '#10b981';
    }
    const sevCell = sev != null
        ? `<span style="font-weight:700;color:${sevColor}">${sev.toFixed(3)}</span>`
        : '—';

    let detailLink = '';
    if (IS_ANALYST && r.sequence_id) {
        const href = SEQUENCE_DETAIL_BASE.replace('__ID__', r.sequence_id);
        detailLink = `<td><a href="${href}" class="btn btn-ghost btn-sm">Detail →</a></td>`;
    }
    const dlabel = r.distilbert_label || '—';
    const dlabelColor = dlabel === 'MALICIOUS' ? '#ef4444' : dlabel === 'BENIGN' ? '#10b981' : '#7d8ea6';
    return `<tr class="row-new" data-id="${r.sequence_id}" data-date="${toDateKey(r.inferred_at)}" data-risk="${r.risk_level || ''}" onclick="handleRowClick(this, '${r.sequence_id}')">
    <td class="monospace" style="font-size:0.75rem">${(r.session_id || r.sequence_id || '').slice(-16)}</td>
    <td>${srcBadge}</td>
    <td>${r.attack_type || '—'}</td>
    <td>${riskBadge}</td>
    <td style="text-align:center">${sevCell}</td>
    <td class="monospace" style="font-size:0.75rem">${r.predicted_next_token || '—'}<br/><span style="color:var(--text-muted)">${r.xlnet_trajectory || ''}</span></td>
    <td style="font-size:0.78rem;font-weight:600;color:${dlabelColor}">${dlabel}</td>
    <td class="prevention-summary-cell" style="font-size:0.78rem;color:var(--text-muted)" title="${(r.prevention_summary||'').replace(/"/g,'&quot;')}">${r.prevention_summary || '—'}</td>
    <td class="monospace" style="font-size:0.75rem">${ts}</td>
    ${detailLink}
  </tr>`;
}

function handleRowClick(row, id) {
    if (!IS_ANALYST) return;
    const href = SEQUENCE_DETAIL_BASE.replace('__ID__', id);
    window.location.href = href;
}

// ── Populate the date filter dropdown ───────────────────────────────────────
function populateDateFilter(rows) {
    const sel = document.getElementById('date-filter');
    if (!sel) return;
    const dates = [...new Set(rows.map(r => toDateKey(r.inferred_at)).filter(Boolean))].sort().reverse();
    dates.forEach(d => {
        if (!sel.querySelector(`option[value="${d}"]`)) {
            const opt = document.createElement('option');
            opt.value = d;
            const label = toDateLabel(d + 'T12:00:00Z');
            opt.textContent = label + ' (' + d + ')';
            sel.appendChild(opt);
        }
    });
}

// ── Render rows into table with date separators ─────────────────────────────
function renderRows(rows, prepend = false) {
    const tbody = document.getElementById('live-tbody');
    if (!tbody) return;

    // If no rows, show "No data available"
    if (!rows || rows.length === 0) {
        if (!prepend) {
            tbody.innerHTML = `<tr>
                <td colspan="10" class="table-empty">
                    <span style="color: var(--text-muted);">📭 No data available</span>
                </td>
            </tr>`;
        }
        return;
    }

    // Count per date
    rows.forEach(r => {
        const dk = toDateKey(r.inferred_at);
        dateCounts[dk] = (dateCounts[dk] || 0) + 1;
    });

    const empty = tbody.querySelector('.table-empty')?.parentElement;
    if (empty) tbody.innerHTML = '';

    // Group rows by date
    const groups = {};
    rows.forEach(r => {
        const dk = toDateKey(r.inferred_at);
        if (!groups[dk]) groups[dk] = [];
        groups[dk].push(r);
    });

    let html = '';
    if (prepend) {
        // For new live events: prepend newest first, inject separator if new date
        Object.keys(groups).sort().reverse().forEach(dk => {
            const existingSep = tbody.querySelector(`tr.date-separator[data-date="${dk}"]`);
            const label = toDateLabel(dk + 'T12:00:00Z');
            if (!existingSep) html += buildDateSeparator(label, dk);
            html += groups[dk].map(buildRow).join('');
        });
        tbody.insertAdjacentHTML('afterbegin', html);
        const allRows = tbody.querySelectorAll('tr[data-id]');
        if (allRows.length > 200) {
            for (let i = 200; i < allRows.length; i++) allRows[i].remove();
        }
        showToast(`${rows.length} new event(s)`);
    } else {
        // For initial load / load-more: append grouped by date
        const sortedDates = Object.keys(groups).sort().reverse();
        sortedDates.forEach(dk => {
            const label = toDateLabel(dk + 'T12:00:00Z');
            const existingSep = tbody.querySelector(`tr.date-separator[data-date="${dk}"]`);
            if (!existingSep) html += buildDateSeparator(label, dk);
            html += groups[dk].map(buildRow).join('');
        });
        tbody.insertAdjacentHTML('beforeend', html);
    }

    populateDateFilter(rows);

    const countEl = document.getElementById('row-count');
    if (countEl) countEl.textContent = tbody.querySelectorAll('tr[data-id]').length + ' sessions';
}

function showToast(msg) {
    const el = document.getElementById('new-events-toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('toast-hidden');
    setTimeout(() => el.classList.add('toast-hidden'), 3000);
}

// ── Fetch feed via REST API ─────────────────────────────────────────────────
async function fetchFeed(options = {}) {
    try {
        const riskFilter = document.getElementById('risk-filter')?.value || '';
        const dateFilter = document.getElementById('date-filter')?.value || '';
        const since = options.since || '';
        let url = `/api/live/feed?limit=${limit}&page=${page}`;
        if (riskFilter) url += `&risk=${riskFilter}`;
        if (dateFilter) url += `&date=${encodeURIComponent(dateFilter)}`;
        if (since)      url += `&since=${encodeURIComponent(since)}`;

        const res = await fetch(url);
        const d   = await res.json();
        if (d.rows && d.rows.length > 0) {
            renderRows(d.rows, options.prepend);
            const mostRecent = d.rows.reduce((a, b) =>
                (b.inferred_at || '') > (a.inferred_at || '') ? b : a, d.rows[0]);
            if (mostRecent.inferred_at > lastSince) lastSince = mostRecent.inferred_at;
        }
        const lmBtn = document.getElementById('load-more-btn');
        if (lmBtn) lmBtn.style.display = d.total > page * limit ? 'block' : 'none';
    } catch (e) {
        console.error('Feed fetch error:', e);
    }
}

// ── WebSocket connection ────────────────────────────────────────────────────
function connectWebSocket() {
    try {
        socket = io('/ws/live', { transports: ['websocket', 'polling'] });
        socket.on('connect',       () => setWsStatus('connected', '🟢 Live feed active'));
        socket.on('disconnect',    () => { setWsStatus('error', '🔴 Disconnected — retrying…'); startPolling(); });
        socket.on('connect_error', () => { setWsStatus('error', '⚠ Polling for updates every 15s'); startPolling(); });
        socket.on('new_predictions', data => {
            if (data.rows && data.rows.length > 0) {
                const risk = document.getElementById('risk-filter')?.value || '';
                let rows = data.rows;
                if (risk) rows = rows.filter(r => r.risk_level === risk);
                if (rows.length > 0) renderRows(rows, true);
            }
        });
    } catch (e) {
        setWsStatus('error', '⚠ Polling for updates');
        startPolling();
    }
}

function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(async () => {
        await fetchFeed({ prepend: true, since: lastSince });
    }, 15000);
}

// ── Filters ─────────────────────────────────────────────────────────────────
function resetAndFetch() {
    const tbody = document.getElementById('live-tbody');
    if (tbody) tbody.innerHTML = '';
    page      = 1;
    lastSince = '';
    fetchFeed();
}

document.getElementById('risk-filter')?.addEventListener('change', resetAndFetch);
document.getElementById('date-filter')?.addEventListener('change', resetAndFetch);

// ── Load more ───────────────────────────────────────────────────────────────
document.getElementById('load-more-btn')?.addEventListener('click', () => {
    page++;
    fetchFeed();
});

// ── Init ────────────────────────────────────────────────────────────────────
setWsStatus('connecting', '⏳ Connecting…');
fetchFeed();
connectWebSocket();
