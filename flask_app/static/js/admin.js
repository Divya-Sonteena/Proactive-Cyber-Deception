/* admin.js — User management for admin settings page */
'use strict';

async function loadUsers() {
    try {
        const res = await fetch('/api/admin/users');
        const d = await res.json();
        renderUsers(d.users || []);
        const cnt = document.getElementById('user-count');
        if (cnt) cnt.textContent = (d.users?.length ?? 0) + ' users';
    } catch (e) {
        console.error('Failed to load users:', e);
    }
}

function renderUsers(users) {
    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;

    if (!users.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="table-empty">No users found.</td></tr>';
        return;
    }

    tbody.innerHTML = users.map(u => {
        const roleOpts = ['student', 'analyst', 'admin'].map(r =>
            `<option value="${r}" ${u.role === r ? 'selected' : ''}>${r}</option>`
        ).join('');
        const roleBadge = `<span class="role-badge role-${u.role}">${u.role.toUpperCase()}</span>`;

        return `<tr>
      <td><strong>${escHtml(u.username)}</strong></td>
      <td>
        ${roleBadge}
        <select class="form-input form-input-sm mt-1 role-select" data-id="${u.id}" style="margin-top:6px">
          ${roleOpts}
        </select>
      </td>
      <td class="monospace">${u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}</td>
      <td>
        <button class="btn btn-primary btn-sm save-btn" data-id="${u.id}">Save</button>
      </td>
    </tr>`;
    }).join('');

    // Wire save buttons
    tbody.querySelectorAll('.save-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.dataset.id;
            const row = btn.closest('tr');
            const role = row.querySelector('.role-select').value;

            btn.textContent = 'Saving…';
            btn.disabled = true;
            try {
                const res = await fetch(`/api/admin/users/${id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ role })
                });
                if (res.ok) {
                    btn.textContent = '✓ Saved';
                    btn.style.background = 'rgba(16,185,129,0.2)';
                    btn.style.color = '#10b981';
                    setTimeout(() => { btn.textContent = 'Save'; btn.disabled = false; btn.style = ''; }, 2000);
                    // Refresh table after save
                    setTimeout(loadUsers, 2200);
                } else {
                    btn.textContent = '✗ Error';
                    setTimeout(() => { btn.textContent = 'Save'; btn.disabled = false; }, 2000);
                }
            } catch (e) {
                btn.textContent = '✗ Failed';
                setTimeout(() => { btn.textContent = 'Save'; btn.disabled = false; }, 2000);
            }
        });
    });
}

function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Init
loadUsers();
