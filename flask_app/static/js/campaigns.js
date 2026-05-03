/**
 * static/js/campaigns.js
 * Powers both /live/campaigns (list) and /live/campaigns/<id> (detail).
 */

"use strict";

// ── Helpers ───────────────────────────────────────────────────────────────────
const RISK_COLOURS = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#f59e0b",
    LOW: "#22c55e",
};

function riskBadge(level) {
    const col = RISK_COLOURS[level] || "#64748b";
    return `<span class="risk-badge" style="background:${col}22;color:${col};border:1px solid ${col}44">${level}</span>`;
}

function formatTime(iso) {
    if (!iso) return "—";
    return iso.replace("T", " ").replace(/\.\d+.*/, "").replace("Z", " UTC");
}

function duration(first, last) {
    if (!first || !last) return "—";
    try {
        const ms = new Date(last) - new Date(first);
        const mins = Math.round(ms / 60000);
        return mins < 60 ? `${mins}m` : `${Math.round(mins / 60)}h ${mins % 60}m`;
    } catch { return "—"; }
}

// ── Campaign List Page (/live/campaigns) ───────────────────────────────────────
async function loadCampaigns() {
    const tbody = document.getElementById("camp-tbody");
    const table = document.getElementById("camp-table");
    const empty = document.getElementById("camp-empty");
    const loading = document.getElementById("camp-loading");
    const counter = document.getElementById("campaign-count");
    const tsEl = document.getElementById("camp-timestamp");

    if (!tbody) return;  // not on list page
    loading.style.display = "flex";
    table.style.display = "none";
    empty.style.display = "none";

    try {
        const r = await fetch("/api/live/campaigns");
        const d = await r.json();
        loading.style.display = "none";
        tsEl.textContent = `Updated ${new Date().toLocaleTimeString()}`;

        const camps = d.campaigns || [];
        counter.textContent = `${d.total || 0} campaign(s)`;

        // Populate stat cards
        const critCount = camps.filter(c => c.campaign_risk === 'CRITICAL').length;
        const highCount = camps.filter(c => c.campaign_risk === 'HIGH').length;
        const totalSessions = camps.reduce((acc, c) => acc + (c.session_count || 0), 0);
        const el = id => document.getElementById(id);
        if (el('camp-stat-critical')) el('camp-stat-critical').textContent = critCount;
        if (el('camp-stat-high'))     el('camp-stat-high').textContent     = highCount;
        if (el('camp-stat-total'))    el('camp-stat-total').textContent    = camps.length;
        if (el('camp-stat-sessions')) el('camp-stat-sessions').textContent = totalSessions;

        if (camps.length === 0) {
            empty.style.display = "flex";
            return;
        }

        table.style.display = "table";
        tbody.innerHTML = camps.map(c => {
            const dur = duration(c.first_seen, c.last_seen);
            const ips = (c.src_ips || []).slice(0, 2).join(", ") + (c.src_ips?.length > 2 ? ` +${c.src_ips.length - 2}` : "");
            const types = (c.attack_types || []).join(", ") || "—";
            const signals = (c.correlation_signals || []).map(s =>
                `<span class="token-chip chip-medium">${s}</span>`
            ).join(" ");
            return `<tr onclick="window.location='/live/campaigns/${c.campaign_id}'" style="cursor:pointer">
        <td>${riskBadge(c.campaign_risk)}</td>
        <td class="mono text-sm">${c.campaign_id}</td>
        <td><strong>${c.session_count}</strong></td>
        <td class="mono text-sm">${ips || "—"}</td>
        <td>${types}</td>
        <td>${dur}</td>
        <td>${signals}</td>
        <td><a class="btn btn-ghost btn-sm" href="/live/campaigns/${c.campaign_id}">Details →</a></td>
      </tr>`;
        }).join("");
    } catch (err) {
        loading.style.display = "none";
        console.error("Campaign load error:", err);
    }
}

// ── Campaign Detail Page (/live/campaigns/<id>) ───────────────────────────────
async function loadCampaignDetail() {
    if (typeof CAMPAIGN_ID === "undefined") return;

    try {
        const r = await fetch(`/api/live/campaigns/${CAMPAIGN_ID}`);
        if (r.status === 404) {
            document.getElementById("camp-title").textContent = "Campaign not found";
            return;
        }
        const c = await r.json();

        // Title and subtitle
        document.getElementById("camp-title").textContent = `Campaign ${c.campaign_id}`;
        document.getElementById("camp-subtitle").textContent =
            `Detected ${formatTime(c.first_seen)}  •  ${c.session_count} linked sessions`;
        document.getElementById("camp-risk-badge").innerHTML = riskBadge(c.campaign_risk);

        // Meta cards
        document.getElementById("meta-sessions").textContent = c.session_count;
        document.getElementById("meta-ips").textContent = (c.src_ips || []).join(", ") || "—";
        document.getElementById("meta-first").textContent = formatTime(c.first_seen);
        document.getElementById("meta-last").textContent = formatTime(c.last_seen);
        document.getElementById("meta-types").textContent = (c.attack_types || []).join(", ") || "—";

        // Correlation signals
        const signalMap = {
            src_ip: { label: "Shared Source IP", icon: "🌐", col: "high" },
            hassh: { label: "Shared SSH fingerprint", icon: "🔑", col: "critical" },
            username: { label: "Shared Username Attempted", icon: "👤", col: "medium" },
        };
        const corrEl = document.getElementById("corr-signals");
        corrEl.innerHTML = (c.correlation_signals || []).map(sig => {
            const s = signalMap[sig] || { label: sig, icon: "⚡", col: "low" };
            return `<span class="token-chip chip-${s.col}" title="${s.label}">${s.icon} ${s.label}</span>`;
        }).join(" ") || "<span class='text-muted'>No signals recorded</span>";

        // Linked sessions table
        const sessions = c.linked_sessions || [];
        const tbody = document.getElementById("sessions-tbody");
        const table = document.getElementById("sessions-table");
        document.getElementById("sessions-loading").style.display = "none";

        if (sessions.length === 0) {
            table.style.display = "none";
            return;
        }
        table.style.display = "table";
        tbody.innerHTML = sessions.map(s => {
            const tokenPreview = (s.tokens || []).slice(0, 6).join(" → ");
            return `<tr>
        <td>${riskBadge(s.risk_level)}</td>
        <td class="mono text-sm">${(s.sequence_id || "").slice(5, 25)}…</td>
        <td>${s.source || "—"}</td>
        <td>${s.attack_type || "—"}</td>
        <td class="mono text-sm">${tokenPreview}</td>
        <td class="text-sm text-muted">${formatTime(s.inferred_at)}</td>
        <td><a class="btn btn-ghost btn-sm" href="/live/${s.sequence_id}">View →</a></td>
      </tr>`;
        }).join("");

    } catch (err) {
        console.error("Campaign detail error:", err);
    }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    if (typeof CAMPAIGN_ID !== "undefined") {
        loadCampaignDetail();
    } else {
        loadCampaigns();
        setInterval(loadCampaigns, 30000);   // refresh list every 30s
    }
});
