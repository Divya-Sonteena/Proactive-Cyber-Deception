/* sequence_detail.js — Full sequence detail page: charts, lifecycle, notes */
'use strict';

const SEVERITY_MAP = {
    SCAN: 1, RECON: 1, FILE_ACC: 1, FILE_OPEN: 1, FILE_CLOSE: 1, SLEEP: 1, SYNC: 1, MEM_MAP: 1, MEM_ALLOC: 1,
    LOGIN_ATT: 2, EXEC: 2, PROC_EXEC: 2, FILE_XFER: 2, PERM_CHG: 2, FILE_WRITE: 2, FILE_MOD: 2, NET_OPEN: 2,
    NET_LISTEN: 2, IPC: 2, PROC_SIG: 2, TUNNEL: 2,
    LOGIN_OK: 3, NET_CONN: 3, NET_CONNECT: 3, NET_BIND: 3, NET_ACCEPT: 3, NET_SEND: 3, NET_RECV: 3,
    PRIV_CHG: 3, PRIV_ESC: 3, PROC_CREATE: 3, FILE_CREATE: 3, FILE_CREAT: 3, MEM_PROT: 3, EXPLOITATION: 3,
    EXEC_FAIL: 4, FILE_DEL: 4, SESS_END: 4, NET_SOCK: 4, NET_CLOSE: 4, PROC_EXIT: 4, MALWARE: 4,
};
const SEV_CLASS = { 1: 'tok-low', 2: 'tok-medium', 3: 'tok-high', 4: 'tok-critical' };
const RISK_COLORS = { LOW: '#10b981', MEDIUM: '#f59e0b', HIGH: '#f97316', CRITICAL: '#ef4444' };

let escalationChart = null, severityChart = null;

// ── Load everything ────────────────────────────────────────────────────────
async function loadSequence() {
    try {
        const res = await fetch(API_BASE);
        if (!res.ok) { showError('Sequence not found.'); return; }
        const d = await res.json();
        document.getElementById('seq-loading').style.display = 'none';
        document.getElementById('seq-content').style.display = '';
        render(d);
        renderExtras(d);
    } catch (e) {
        showError('Failed to load sequence data.');
    }
}

function showError(msg) {
    document.getElementById('seq-loading').textContent = '⚠ ' + msg;
}

function render(d) {
    // 1. Overview
    document.getElementById('ov-session').textContent = d.session_id || d.sequence_id;
    document.getElementById('ov-attack').textContent = d.attack_type || '—';
    document.getElementById('ov-time').textContent = d.inferred_at ? new Date(d.inferred_at).toLocaleString() : '—';
    document.getElementById('ov-source').textContent = (d.source || '—').toUpperCase();

    const riskEl = document.getElementById('ov-risk');
    riskEl.textContent = d.risk_level || '—';
    riskEl.className = `risk-badge risk-${d.risk_level}`;

    // Badges
    // Update risk badge in badges area
    const badges = document.getElementById('ov-badges');
    if (badges) {
        // Insert risk badge before the anomaly span (prepend)
        const existing = badges.querySelector('.risk-badge');
        if (!existing) {
            badges.insertAdjacentHTML('afterbegin',
                `<span class="risk-badge risk-${d.risk_level}">${d.risk_level}</span>`);
        } else {
            existing.textContent = d.risk_level;
            existing.className = `risk-badge risk-${d.risk_level}`;
        }
    }

    // 2. Token flow
    renderTokenFlow(d.token_flow || [], d.predicted_next_token);

    // 3. Model outputs
    setBar('distilbert-bar', d.attack_prob);
    document.getElementById('distilbert-val').textContent = pct(d.attack_prob);
    document.getElementById('distilbert-verdict').textContent = d.distilbert_label || '—';
    document.getElementById('distilbert-verdict').style.color =
        d.distilbert_label === 'MALICIOUS' ? '#ef4444' : '#10b981';
    const nextTag = document.getElementById('next-token-tag');
    nextTag.textContent = `${d.predicted_next_token || '—'}  ${d.xlnet_trajectory || ''}`;


    // 4. Severity breakdown
    document.getElementById('sev-token').textContent = fmt(d.token_severity_mean);
    document.getElementById('sev-atk').textContent = pct(d.attack_prob);
    document.getElementById('sev-combined').textContent = fmt(d.combined_severity);
    const sevRisk = document.getElementById('sev-risk');
    sevRisk.textContent = d.risk_level || '—';
    sevRisk.className = `risk-badge risk-${d.risk_level}`;

    renderSeverityDoughnut(d);

    // 5. Escalation chart
    renderEscalation(d.escalation || []);

    // 6. Prevention
    renderPrevention(d.prevention || {});

    // 7. Raw metadata (admin) — sourced from MongoDB live_predictions
    if (IS_ADMIN) {
        const raw = document.getElementById('raw-metadata');
        if (raw) {
            const meta = {
                // Identity
                sequence_id: d.sequence_id,
                session_id: d.session_id,
                source: d.source,
                src_ip: d.src_ip,
                // Timing
                inferred_at: d.inferred_at,
                start_time: d.start_time,
                end_time: d.end_time,
                // Tokens & classification
                event_tokens: d.event_tokens,
                token_flow: d.token_flow,
                attack_type: d.attack_type,
                // ML predictions
                distilbert_label: d.distilbert_label,
                attack_prob: d.attack_prob,
                anomaly_score: d.anomaly_score,
                predicted_next_token: d.predicted_next_token,
                xlnet_trajectory: d.xlnet_trajectory,
                model_agreement: d.agreement,
                // Severity
                token_severity_mean: d.token_severity_mean,
                combined_severity: d.combined_severity,
                risk_level: d.risk_level,
                perplexity: d.perplexity,
                // Session details (cowrie-specific)
                login_success: d.login_success,
                username: d.username,
                commands: d.commands,
                hassh: d.hassh,
                arch: d.arch,
                // Session details (dionaea-specific)
                protocol: d.protocol,
                dst_port: d.dst_port,
                exploit_url: d.exploit_url,
                malware_sha256: d.malware_sha256,
                num_events: d.num_events,
                is_live: d.is_live,
            };
            raw.innerHTML = `<pre style="white-space:pre-wrap;word-break:break-all;font-size:0.78rem;color:var(--text-muted)">${escHtml(JSON.stringify(meta, null, 2))}</pre>`;
        }
    }

    // 8. Notes
    renderNotes(d.notes || []);
}

// ── Token flow ─────────────────────────────────────────────────────────────
function renderTokenFlow(tokens, nextToken) {
    const container = document.getElementById('token-flow-container');
    if (!container) return;
    const chips = tokens.map(t => {
        const sev = SEVERITY_MAP[t] || 1;
        return `<span class="token-chip ${SEV_CLASS[sev]}" title="Severity: ${sev}">${t}</span>
            <span class="flow-arrow">→</span>`;
    }).join('');
    const predicted = nextToken
        ? `<span class="token-chip tok-predicted">? ${nextToken}</span>`
        : '';
    container.innerHTML = chips + predicted;
}

// ── Bars ───────────────────────────────────────────────────────────────────
function setBar(id, val) {
    const el = document.getElementById(id);
    if (el) el.style.setProperty('--fill', pct(val || 0));
}

// ── Severity doughnut ──────────────────────────────────────────────────────
function renderSeverityDoughnut(d) {
    const ctx = document.getElementById('severity-chart');
    if (!ctx) return;
    const norm = d.combined_severity > 0 ? d.combined_severity : 1;
    const tokenContrib = ((d.token_severity_mean - 1) / 3) * 0.25 / norm;
    const atkContrib = d.attack_prob * 1.50 / norm;
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Token Severity', 'Attack Prob'],
            datasets: [{
                data: [tokenContrib, atkContrib],
                backgroundColor: ['#3b82f6', '#ef4444'], borderWidth: 0
            }],
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '65%',
            plugins: { legend: { position: 'bottom', labels: { color: '#7d8ea6', boxWidth: 10, padding: 8 } } }
        },
    });
}

// ── Escalation graph ───────────────────────────────────────────────────────
function renderEscalation(escalation) {
    const ctx = document.getElementById('escalation-chart');
    if (!ctx || !escalation.length) return;
    const labels = escalation.map(e => e.token);
    const data = escalation.map(e => e.cumulative_avg);
    if (escalationChart) escalationChart.destroy();
    escalationChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Cumulative Risk Score',
                data,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59,130,246,0.08)',
                tension: 0.35, fill: true, pointRadius: 4,
                pointBackgroundColor: data.map(v =>
                    v >= 2.0 ? '#ef4444' : v >= 1.2 ? '#f97316' : v >= 0.5 ? '#f59e0b' : '#10b981'),
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: c => `Severity: ${c.raw.toFixed(3)}`
                    }
                }
            },
            scales: {
                x: { ticks: { color: '#7d8ea6', maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: {
                    ticks: { color: '#7d8ea6' }, grid: { color: 'rgba(255,255,255,0.04)' },
                    min: 0,
                    suggestedMax: 3,
                }
            }
        }
    });
}

// ── Prevention ─────────────────────────────────────────────────────────────
function renderPrevention(prev) {
    const trigger = document.getElementById('trigger-explanation');
    if (trigger) trigger.textContent = prev.trigger_explanation || '';

    ['access_control', 'network_security', 'host_hardening'].forEach((key, i) => {
        const ids = ['prev-access', 'prev-network', 'prev-host'];
        const el = document.getElementById(ids[i]);
        if (!el) return;
        const items = prev[key] || [];
        el.innerHTML = items.map(([priority, text]) =>
            `<div class="prevention-item">
        <span class="priority-label priority-${priority.replace(' ', '-')}">${priority}</span>
        <div class="prevention-text">${text}</div>
      </div>`
        ).join('');
    });

    // Show AI source badge
    const badge = document.getElementById('prevention-source-badge');
    if (badge) {
        const src = prev.source || '';
        if (src === 'groq' || src === 'gemini') {
            badge.textContent = '✦ Groq AI';
            badge.style.cssText = 'display:inline-flex;background:rgba(59,130,246,0.15);color:#3b82f6;border-color:rgba(59,130,246,0.3)';
        } else if (src === 'groq_cached' || src === 'gemini_cached') {
            badge.textContent = '✦ Groq AI (cached)';
            badge.style.cssText = 'display:inline-flex;background:rgba(16,185,129,0.1);color:#10b981;border-color:rgba(16,185,129,0.3)';
        } else {
            badge.textContent = '⊟ Static Template';
            badge.style.cssText = 'display:inline-flex;background:rgba(125,142,166,0.12);color:#7d8ea6;border-color:rgba(125,142,166,0.2)';
        }
    }
}

// ── Regenerate prevention with fresh Gemini call ───────────────────────────
async function regeneratePrevention() {
    const btn = document.getElementById('btn-regenerate');
    const badge = document.getElementById('prevention-source-badge');
    if (btn) { btn.disabled = true; btn.textContent = '✦ Generating…'; }
    if (badge) { badge.textContent = '⟳ Calling Groq AI…'; badge.style.display = 'inline-flex'; }

    try {
        const r = await fetch(`/api/live/sequence/${SEQUENCE_ID}/prevention/regenerate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });
        if (!r.ok) {
            const err = await r.json();
            alert(`Regenerate failed: ${err.error || r.status}`);
            return;
        }
        const prev = await r.json();
        renderPrevention(prev);
    } catch (err) {
        console.error('Regenerate error:', err);
        alert(`Network error: ${err.message}`);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = '✦ Regenerate with AI'; }
    }
}


// ── Notes ──────────────────────────────────────────────────────────────────
function renderNotes(notes) {
    const container = document.getElementById('notes-container');
    if (!container) return;
    if (!notes.length) {
        container.innerHTML = '<div style="color:var(--text-muted);font-size:0.82rem;padding:4px 0">No notes yet.</div>';
        return;
    }
    container.innerHTML = notes.map(n => `
    <div class="note-card">
      <div class="note-header">
        <span class="note-author">@${n.author}</span>
        <span class="badge">${n.role}</span>
        <span>${new Date(n.created_at).toLocaleString()}</span>
      </div>
      <div class="note-body">${escHtml(n.text)}</div>
    </div>`).join('');
}

document.getElementById('add-note-form')?.addEventListener('submit', async function (e) {
    e.preventDefault();
    const txt = document.getElementById('note-text').value.trim();
    if (!txt) return;
    try {
        const res = await fetch(NOTES_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: txt })
        });
        const note = await res.json();
        document.getElementById('note-text').value = '';
        const container = document.getElementById('notes-container');
        const empty = container.querySelector('.text-muted');
        if (empty) container.innerHTML = '';
        container.insertAdjacentHTML('beforeend', `
      <div class="note-card">
        <div class="note-header">
          <span class="note-author">@${note.author}</span>
          <span class="badge">${note.role}</span>
          <span>${new Date(note.created_at).toLocaleString()}</span>
        </div>
        <div class="note-body">${escHtml(note.text)}</div>
      </div>`);
    } catch (e) { console.error('Note submit failed:', e); }
});

// ── Helpers ────────────────────────────────────────────────────────────────
function pct(v) { return v != null ? (v * 100).toFixed(1) + '%' : '—'; }
function fmt(v) { return v != null ? Number(v).toFixed(4) : '—'; }
function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}


// ── Automated Response (Feature 5) ────────────────────────────────────────
async function respondAction(action) {
    const labels = {
        block_ip: 'Block IP via firewall',
        watch_ip: 'Add to watchlist',
        note_only: 'Log action only',
    };
    const confirmed = confirm(
        `Action: ${labels[action] || action}\n\nThis action will be permanently audit-logged. Proceed?`
    );
    if (!confirmed) return;

    // Disable all respond buttons during request
    ['btn-block', 'btn-watch', 'btn-note'].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.disabled = true; el.textContent += ' …'; }
    });

    const resultEl = document.getElementById('respond-result');

    try {
        const r = await fetch(RESPOND_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        const d = await r.json();

        if (resultEl) {
            resultEl.style.display = 'block';
            if (d.ok) {
                resultEl.className = 'respond-result respond-success';
                resultEl.innerHTML = `
                    <strong>✓ Action executed</strong><br>
                    Action: <code>${d.action}</code>  |
                    Target: <code>${d.target_ip || 'n/a'}</code><br>
                    ${d.os_result?.command ? `Command: <code>${escHtml(d.os_result.command)}</code>` : ''}
                    <br><span class="text-muted">Performed by ${d.performed_by} — logged to Response Audit</span>
                `;
            } else {
                resultEl.className = 'respond-result respond-error';
                resultEl.innerHTML = `
                    <strong>⚠ Action attempted</strong> · ${d.error || d.os_result?.error || 'Unknown error'}<br>
                    <span class="text-muted">Logged to Response Audit regardless of OS result.</span>
                `;
            }
        }

    } catch (err) {
        if (resultEl) {
            resultEl.style.display = 'block';
            resultEl.className = 'respond-result respond-error';
            resultEl.textContent = `Network error: ${err.message}`;
        }
    } finally {
        const origLabels = { 'btn-block': '🚫 Block IP (Firewall)', 'btn-watch': '👁 Add to Watchlist', 'btn-note': '📋 Log Action Only' };
        ['btn-block', 'btn-watch', 'btn-note'].forEach(id => {
            const el = document.getElementById(id);
            if (el) { el.disabled = false; el.textContent = origLabels[id]; }
        });
    }
}

// ── Init ───────────────────────────────────────────────────────────────────
loadSequence();


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Feature 3 — MITRE ATT&CK Panel
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const TACTIC_COLORS = {
    'Reconnaissance': '#6366f1',
    'Initial Access': '#f97316',
    'Execution': '#ef4444',
    'Persistence': '#a855f7',
    'Defense Evasion': '#8b5cf6',
    'Credential Access': '#ec4899',
    'Discovery': '#3b82f6',
    'Lateral Movement': '#14b8a6',
    'Collection': '#f59e0b',
    'Command and Control': '#0ea5e9',
    'Exfiltration': '#84cc16',
    'Impact': '#dc2626',
    'Resource Development': '#78716c',
    'Defense Evasion / Persistence': '#8b5cf6',
};

function renderMitre(techniques) {
    const el = document.getElementById('mitre-content');
    if (!el) return;

    if (!techniques || techniques.length === 0) {
        el.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;padding:4px 0">No MITRE ATT&CK techniques mapped for this sequence.</p>';
        return;
    }

    const cards = techniques.map(t => {
        const color = TACTIC_COLORS[t.tactic] || '#7d8ea6';
        return `
        <a href="${t.url}" target="_blank" rel="noopener noreferrer" class="mitre-card" style="
            display:flex;align-items:flex-start;gap:12px;padding:12px 16px;
            border:1px solid rgba(255,255,255,0.07);border-radius:8px;
            background:rgba(255,255,255,0.03);text-decoration:none;color:inherit;
            transition:background 0.15s;margin-bottom:8px">
            <div style="flex-shrink:0;width:60px;text-align:center">
                <span style="font-family:monospace;font-size:0.78rem;color:${color};
                    font-weight:700;background:${color}22;padding:2px 8px;border-radius:4px;
                    white-space:nowrap">${t.technique_id}</span>
            </div>
            <div style="flex:1;min-width:0">
                <div style="font-weight:600;font-size:0.9rem;margin-bottom:2px">${t.technique_name}</div>
                <span style="font-size:0.76rem;color:${color};font-weight:500;
                    background:${color}18;padding:1px 7px;border-radius:3px;white-space:nowrap">${t.tactic}</span>
            </div>
            <span style="font-size:0.75rem;color:var(--text-muted);flex-shrink:0;align-self:center">↗</span>
        </a>`;
    }).join('');

    el.innerHTML = `<div style="display:flex;flex-direction:column;gap:0">${cards}</div>`;
}

// Wire MITRE into the main render function (called after data loads)
function renderExtras(d) {
    renderMitre(d.mitre_techniques || []);
    loadProfilePanel(d.src_ip);
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Feature 4 — Attacker Behavioral Profile Panel
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function loadProfilePanel(srcIp) {
    const el = document.getElementById('profile-content');
    if (!el) return;
    if (!srcIp) {
        el.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;padding:4px 0">IP not available for this role.</p>';
        return;
    }
    try {
        const r = await fetch(`/api/live/profile/${encodeURIComponent(srcIp)}`);
        if (r.status === 404) {
            el.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem;padding:4px 0">No profile yet for this IP — will build after more sessions.</p>';
            return;
        }
        const p = await r.json();
        const riskColor = { LOW: '#10b981', MEDIUM: '#f59e0b', HIGH: '#f97316', CRITICAL: '#ef4444' };
        const peakColor = riskColor[p.peak_risk] || '#7d8ea6';

        // Attack type breakdown bars
        const typeBars = Object.entries(p.attack_type_counts || {})
            .sort((a, b) => b[1] - a[1])
            .map(([type, count]) => {
                const pct = p.session_count > 0 ? Math.round(count / p.session_count * 100) : 0;
                return `<div style="margin-bottom:6px">
                    <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:2px">
                        <span>${type}</span><span style="color:var(--text-muted)">${count} sessions (${pct}%)</span>
                    </div>
                    <div style="background:rgba(255,255,255,0.06);border-radius:3px;height:5px">
                        <div style="width:${pct}%;background:#3b82f6;height:5px;border-radius:3px;transition:width 0.4s"></div>
                    </div>
                </div>`;
            }).join('');

        // Token signature chips
        const sigChips = (p.token_signature || []).map(t =>
            `<span style="font-size:0.72rem;background:rgba(99,102,241,0.15);color:#818cf8;
                padding:2px 8px;border-radius:4px;white-space:nowrap">${t}</span>`
        ).join('');

        el.innerHTML = `
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px">
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
                    border-radius:8px;padding:12px;text-align:center">
                    <div style="font-size:1.6rem;font-weight:700;color:#3b82f6">${p.session_count}</div>
                    <div style="font-size:0.75rem;color:var(--text-muted)">Total Sessions</div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
                    border-radius:8px;padding:12px;text-align:center">
                    <div style="font-size:1.4rem;font-weight:700;color:${peakColor}">${p.peak_risk}</div>
                    <div style="font-size:0.75rem;color:var(--text-muted)">Peak Risk</div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
                    border-radius:8px;padding:12px;text-align:center">
                    <div style="font-size:1.2rem;font-weight:700;color:${p.repeat_attacker ? '#ef4444' : '#10b981'}">
                        ${p.repeat_attacker ? '🔁 Repeat' : '🆕 New'}
                    </div>
                    <div style="font-size:0.75rem;color:var(--text-muted)">Attacker Type</div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
                    border-radius:8px;padding:12px;text-align:center">
                    <div style="font-size:0.75rem;color:#7d8ea6;margin-bottom:2px">Sources</div>
                    <div style="font-size:0.82rem;font-weight:600">${(p.sources || []).join(', ') || '—'}</div>
                </div>
            </div>

            <div style="margin-bottom:16px">
                <div style="font-size:0.8rem;font-weight:600;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em">Attack Type Distribution</div>
                ${typeBars || '<p style="color:var(--text-muted);font-size:0.85rem">No data</p>'}
            </div>

            <div>
                <div style="font-size:0.8rem;font-weight:600;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em">Behavioral Token Signature</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px">${sigChips || '<span style="color:var(--text-muted);font-size:0.85rem">No tokens recorded</span>'}</div>
            </div>

            <div style="margin-top:12px;font-size:0.73rem;color:var(--text-muted)">
                First seen: ${p.first_seen ? new Date(p.first_seen).toLocaleString() : '—'} &nbsp;·&nbsp;
                Last seen: ${p.last_seen ? new Date(p.last_seen).toLocaleString() : '—'}
            </div>`;
    } catch (e) {
        el.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem">Could not load attacker profile.</p>';
    }
}

