/* reports.js — Models page metrics + Reports daily download table */
'use strict';

// ── Utilities ─────────────────────────────────────────────────────────────
const pct  = v => v != null ? (v * 100).toFixed(2) + '%' : '—';
const fmt2 = v => v != null ? Number(v).toFixed(2) : '—';
const fmt4 = v => v != null ? Number(v).toFixed(4) : '—';
const setText = (id, t) => { const e = document.getElementById(id); if (e) e.textContent = t; };
const setHtml = (id, h) => { const e = document.getElementById(id); if (e) e.innerHTML = h; };

function metricRow(label, val) {
    return `<div class="metric-row"><span class="metric-key">${label}</span><span class="metric-val">${val}</span></div>`;
}
function cmHtml(cm) {
    if (!cm) return '<p style="color:var(--text-muted)">No data</p>';
    return `
    <div class="cm-cell cm-tp"><div class="cm-label">True Positive</div><div class="cm-value">${cm.tp ?? '—'}</div></div>
    <div class="cm-cell cm-fp"><div class="cm-label">False Positive</div><div class="cm-value">${cm.fp ?? '—'}</div></div>
    <div class="cm-cell cm-fn"><div class="cm-label">False Negative</div><div class="cm-value">${cm.fn ?? '—'}</div></div>
    <div class="cm-cell cm-tn"><div class="cm-label">True Negative</div><div class="cm-value">${cm.tn ?? '—'}</div></div>`;
}

// ── Tab handling (Models page) ────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${tab}`)?.classList.add('active');
        if (tab === 'distilbert' && !window._dbLoaded) loadDistilBERT();
        if (tab === 'xlnet'      && !window._xlLoaded) loadXLNet();
    });
});

// ── DistilBERT (Models page) ──────────────────────────────────────────────
async function loadDistilBERT() {
    window._dbLoaded = true;
    try {
        const d = await fetch('/api/reports/distilbert').then(r => r.json());
        document.getElementById('db-loading').style.display = 'none';
        document.getElementById('db-content').style.display = '';

        if (d.overall) {
            setHtml('db-metrics', [
                ['accuracy','Accuracy'], ['precision','Precision'], ['recall','Recall'],
                ['f1','F1 Score'], ['f1_macro','F1 Macro'], ['roc_auc','ROC-AUC']
            ].map(([k,l]) => metricRow(l, pct(d.overall[k]))).join('') +
            (d.overall.mcc != null ? metricRow('MCC', d.overall.mcc.toFixed(4)) : ''));
        }

        const cmEl = document.getElementById('db-cm');
        if (cmEl) cmEl.innerHTML = cmHtml(d.confusion_matrix);

        const distEl = document.getElementById('db-dist-chart');
        if (distEl && d.class_distribution) {
            new Chart(distEl, {
                type: 'doughnut',
                data: { labels: ['Benign', 'Malicious'],
                    datasets: [{ data: [d.class_distribution.n_benign, d.class_distribution.n_malicious],
                        backgroundColor: ['#3b82f6', '#ef4444'], borderWidth: 0 }] },
                options: { responsive: true, maintainAspectRatio: false, cutout: '60%',
                    plugins: { legend: { position: 'bottom', labels: { color: '#7d8ea6', boxWidth: 10 } } } }
            });
        }

        const tsEl = document.getElementById('db-threshold-chart');
        if (tsEl && d.threshold_sweep) {
            new Chart(tsEl, { type: 'line',
                data: { labels: d.threshold_sweep.map(s => s.threshold.toFixed(2)),
                    datasets: [
                        { label: 'F1',        data: d.threshold_sweep.map(s => s.f1),        borderColor: '#3b82f6', tension: 0.3, fill: false },
                        { label: 'Precision', data: d.threshold_sweep.map(s => s.precision), borderColor: '#10b981', tension: 0.3, fill: false },
                        { label: 'Recall',    data: d.threshold_sweep.map(s => s.recall),    borderColor: '#f59e0b', tension: 0.3, fill: false },
                    ]},
                options: { responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom', labels: { color: '#7d8ea6', boxWidth: 10 } } },
                    scales: {
                        x: { ticks: { color: '#7d8ea6' }, grid: { color: 'rgba(255,255,255,0.04)' } },
                        y: { ticks: { color: '#7d8ea6' }, grid: { color: 'rgba(255,255,255,0.04)' }, min: 0, max: 1 }
                    }}
            });
        }

        if (d.per_source) {
            setHtml('db-per-source', Object.entries(d.per_source).map(([k, m]) =>
                metricRow(`${k} (n=${m.n_samples})`, `Acc: ${pct(m.accuracy)} / F1: ${pct(m.f1)}`)
            ).join(''));
        }

        if (d.bootstrap_ci) {
            setHtml('db-ci', Object.entries(d.bootstrap_ci).map(([k,v]) =>
                metricRow(k, `${fmt4(v.mean)} [${fmt4(v.ci_lower)}, ${fmt4(v.ci_upper)}]`)
            ).join(''));
        }
    } catch (e) { console.error('DistilBERT:', e); }
}

// ── XLNet (Models page) ───────────────────────────────────────────────────
async function loadXLNet() {
    window._xlLoaded = true;
    try {
        const d = await fetch('/api/reports/xlnet').then(r => r.json());
        document.getElementById('xl-loading').style.display = 'none';
        document.getElementById('xl-content').style.display = '';

        const sl = t => `<div style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin:10px 0 4px">${t}</div>`;
        const rows = [
            sl('Language Model Quality'),
            d.perplexity_mean   != null ? metricRow('Perplexity (mean)',   fmt2(d.perplexity_mean))   : '',
            d.perplexity_median != null ? metricRow('Perplexity (median)', fmt2(d.perplexity_median)) : '',
            sl('Anomaly Detection'),
            d.threshold != null ? metricRow('Threshold', d.threshold) : '',
            d.accuracy  != null ? metricRow('Accuracy',  pct(d.accuracy))  : '',
            d.precision != null ? metricRow('Precision', pct(d.precision)) : '',
            d.recall    != null ? metricRow('Recall',    pct(d.recall))    : '',
            d.f1        != null ? metricRow('F1 Score',  pct(d.f1))        : '',
            d.mcc       != null ? metricRow('MCC',       d.mcc.toFixed(4)) : '',
        ];
        const h = d.hybrid_detection || {};
        if (h.f1 != null) {
            rows.push(sl('Hybrid (DistilBERT + XLNet)'));
            rows.push(metricRow('F1 Score', pct(h.f1)));
            rows.push(metricRow('Accuracy', pct(h.accuracy)));
            rows.push(metricRow('Recall',   pct(h.recall)));
        }
        setHtml('xl-metrics', rows.join(''));

        const xlCmEl = document.getElementById('xl-cm');
        if (xlCmEl && d.confusion_matrix) xlCmEl.innerHTML = cmHtml(d.confusion_matrix);
    } catch (e) { console.error('XLNet:', e); }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  REPORTS PAGE — Daily Excel Download Table
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const RISK_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' };

function riskBar(c, h, m, l) {
    const total = (c||0) + (h||0) + (m||0) + (l||0) || 1;
    const seg = (v, col) => v
        ? `<span style="width:${(v/total*100).toFixed(1)}%;background:${col};display:inline-block;height:100%;border-radius:2px" title="${v}"></span>`
        : '';
    return `<div style="width:100%;height:8px;background:rgba(255,255,255,0.06);border-radius:4px;overflow:hidden;display:flex">
        ${seg(c,'#ef4444')}${seg(h,'#f97316')}${seg(m,'#f59e0b')}${seg(l,'#10b981')}
    </div>`;
}

function fmtDate(d) {
    const [y,mo,day] = d.split('-');
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return `${day} ${months[parseInt(mo)-1]} ${y}`;
}

let _allRows = [];

function renderTable(rows) {
    const tbody = document.getElementById('rpt-tbody');
    if (!tbody) return;
    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:2rem">No results match your filter.</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(({ date, c }) => {
        const { total = 0 } = c;
        const isToday = date === new Date().toISOString().slice(0, 10);
        return `<tr class="${isToday ? 'rpt-today' : ''}">
            <td>
                <span class="rpt-date">${fmtDate(date)}</span>
                ${isToday ? '<span class="rpt-today-badge">Today</span>' : ''}
            </td>
            <td class="rpt-num">${total.toLocaleString()}</td>
            <td>
                <a href="/api/live/export/excel?date=${date}" class="btn-dl" download>
                    <span class="dl-icon">⬇</span> Download Excel
                </a>
            </td>
        </tr>`;
    }).join('');
}


async function loadReportDates() {
    try {
        const data = await fetch('/api/live/export/dates').then(r => r.json());
        document.getElementById('rpt-loading').style.display = 'none';

        if (!data.dates || !data.dates.length) {
            document.getElementById('rpt-empty').style.display = '';
            return;
        }

        document.getElementById('rpt-table-wrap').style.display = '';
        _allRows = data.dates.map(d => ({ date: d, c: data.counts[d] || {} }));
        renderTable(_allRows);

        // Search filter
        const searchEl = document.getElementById('rpt-search');
        if (searchEl) {
            searchEl.addEventListener('input', () => {
                const q = searchEl.value.trim().toLowerCase();
                renderTable(q ? _allRows.filter(r => r.date.includes(q)) : _allRows);
            });
        }
    } catch (e) { console.error('Dates load error:', e); }
}

// ── Init ──────────────────────────────────────────────────────────────────
const firstTab = document.querySelector('.tab-btn.active')?.dataset?.tab;
if (firstTab === 'distilbert') loadDistilBERT();
if (firstTab === 'xlnet')      loadXLNet();

if (document.getElementById('rpt-tbody')) loadReportDates();
