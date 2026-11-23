(() => {
  const TOKEN_KEY = "aegisrs_token";
  let token = sessionStorage.getItem(TOKEN_KEY) || "";
  let ws = null;
  let paused = false;
  let allEvents = [];
  let pollTimer = null;

  const authOverlay = document.getElementById("auth-overlay");
  const appShell = document.getElementById("app");
  const loginForm = document.getElementById("login-form");
  const authError = document.getElementById("auth-error");
  const alertSearch = document.getElementById("alert-search");
  const severityFilter = document.getElementById("severity-filter");

  async function apiFetch(path, opts = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(path, { ...opts, headers });
    if (res.status === 401) {
      logout();
      throw new Error("Unauthorized");
    }
    return res;
  }

  function logout() {
    token = "";
    sessionStorage.removeItem(TOKEN_KEY);
    if (ws) ws.close();
    if (pollTimer) clearInterval(pollTimer);
    appShell.hidden = true;
    authOverlay.hidden = false;
  }

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    authError.hidden = true;
    const password = document.getElementById("password-input").value;
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (!res.ok) {
        authError.textContent = res.status === 429
          ? "Too many attempts. Locked out for 5 minutes."
          : "Invalid password or token.";
        authError.hidden = false;
        return;
      }
      const data = await res.json();
      token = data.token;
      sessionStorage.setItem(TOKEN_KEY, token);
      document.getElementById("password-input").value = "";
      enterApp();
    } catch (_) {
      authError.textContent = "Connection failed.";
      authError.hidden = false;
    }
  });

  document.getElementById("btn-logout").addEventListener("click", logout);

  document.getElementById("btn-pause-fim").addEventListener("click", async () => {
    if (paused) {
      await apiFetch("/api/fim/resume", { method: "POST" });
    } else {
      await apiFetch("/api/fim/pause", {
        method: "POST",
        body: JSON.stringify({ duration_secs: 900 }),
      });
    }
    refreshAll();
  });

  document.getElementById("manual-ban-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = document.getElementById("manual-ban-ip");
    const ip = input.value.trim();
    if (!ip) return;
    await apiFetch("/api/bans", {
      method: "POST",
      body: JSON.stringify({ ip, reason: "Manual Grafana Console Ban", duration_secs: 86400 }),
    });
    input.value = "";
    refreshAll();
  });

  alertSearch.addEventListener("input", renderAlertsTable);
  severityFilter.addEventListener("change", renderAlertsTable);

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderRpsChart(history) {
    const svg = document.getElementById("rps-chart");
    const data = Array.isArray(history) && history.length > 1 ? history : [0, 0, 0, 0, 0];
    const w = 640;
    const h = 190;
    const padL = 34;
    const padR = 10;
    const padT = 12;
    const padB = 18;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;

    const maxVal = Math.max(5, ...data);
    const curVal = data[data.length - 1] || 0;
    const avgVal = (data.reduce((a, b) => a + b, 0) / data.length).toFixed(1);

    document.getElementById("rps-cur").textContent = curVal;
    document.getElementById("rps-max").textContent = Math.max(...data);
    document.getElementById("rps-avg").textContent = avgVal;

    const points = data.map((v, idx) => {
      const x = padL + (idx / Math.max(1, data.length - 1)) * plotW;
      const y = padT + plotH - (v / maxVal) * plotH;
      return [x.toFixed(1), y.toFixed(1)];
    });

    const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p[0]},${p[1]}`).join(" ");
    const areaPath = `${linePath} L${points[points.length - 1][0]},${padT + plotH} L${points[0][0]},${padT + plotH} Z`;

    let grid = "";
    for (let i = 0; i <= 4; i++) {
      const y = padT + (i / 4) * plotH;
      const label = Math.round(maxVal * (1 - i / 4));
      grid += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="oklch(0.24 0.012 260)" stroke-dasharray="2,3" />`;
      grid += `<text x="${padL - 6}" y="${y + 4}" text-anchor="end" fill="oklch(0.60 0.015 250)" font-size="10" font-family="monospace">${label}</text>`;
    }

    svg.innerHTML = `
      <defs>
        <linearGradient id="rpsGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="oklch(0.76 0.14 205)" stop-opacity="0.38" />
          <stop offset="100%" stop-color="oklch(0.76 0.14 205)" stop-opacity="0.02" />
        </linearGradient>
      </defs>
      ${grid}
      <path d="${areaPath}" fill="url(#rpsGrad)" />
      <path d="${linePath}" fill="none" stroke="oklch(0.76 0.14 205)" stroke-width="2" />
    `;
  }

  function renderTopIps(events) {
    const container = document.getElementById("top-ips-list");
    const counts = {};
    events.forEach((ev) => {
      if (ev.source_ip) counts[ev.source_ip] = (counts[ev.source_ip] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    if (sorted.length === 0) {
      container.innerHTML = '<div class="empty-msg">No attacker IPs observed yet.</div>';
      return;
    }
    const maxHits = sorted[0][1];
    container.innerHTML = "";
    sorted.forEach(([ip, hits]) => {
      const pct = Math.max(8, Math.round((hits / maxHits) * 100));
      const row = document.createElement("div");
      row.className = "gauge-row";
      row.innerHTML = `
        <div class="gauge-meta"><span>${escapeHtml(ip)}</span><span>${hits} hits</span></div>
        <div class="gauge-track"><div class="gauge-fill" style="width:${pct}%"></div></div>
      `;
      container.appendChild(row);
    });
  }

  function renderEventRow(ev) {
    const tr = document.createElement("tr");
    const ts = new Date(ev.timestamp).toLocaleTimeString();
    const ip = ev.source_ip || "-";
    const banBtn = ev.source_ip
      ? `<button class="btn btn-danger btn-sm" data-ban-ip="${escapeHtml(ev.source_ip)}">Ban IP</button>`
      : `<span class="muted">-</span>`;

    tr.innerHTML = `
      <td class="mono">${ts}</td>
      <td><span class="badge badge-${ev.severity}">${ev.severity}</span></td>
      <td class="mono">${escapeHtml(ev.category)}</td>
      <td class="mono">${escapeHtml(ip)}</td>
      <td><strong>${escapeHtml(ev.title)}</strong><br><span class="muted">${escapeHtml(ev.description)}</span></td>
      <td>${banBtn}</td>
    `;
    const btn = tr.querySelector("[data-ban-ip]");
    if (btn) {
      btn.addEventListener("click", async () => {
        await apiFetch("/api/bans", {
          method: "POST",
          body: JSON.stringify({ ip: ev.source_ip, reason: ev.title, duration_secs: 86400 }),
        });
        refreshAll();
      });
    }
    return tr;
  }

  function renderAlertsTable() {
    const tbody = document.getElementById("alerts-tbody");
    const q = alertSearch.value.trim().toLowerCase();
    const sev = severityFilter.value;

    const filtered = allEvents.filter((ev) => {
      if (sev !== "ALL" && ev.severity !== sev) return false;
      if (!q) return true;
      return (
        (ev.source_ip || "").toLowerCase().includes(q) ||
        (ev.title || "").toLowerCase().includes(q) ||
        (ev.description || "").toLowerCase().includes(q) ||
        (ev.category || "").toLowerCase().includes(q)
      );
    });

    tbody.innerHTML = "";
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No matching security alerts.</td></tr>';
      return;
    }
    filtered.slice(0, 100).forEach((ev) => tbody.appendChild(renderEventRow(ev)));
  }

  async function refreshAll() {
    try {
      const [statusRes, eventsRes, bansRes] = await Promise.all([
        apiFetch("/api/status"),
        apiFetch("/api/events"),
        apiFetch("/api/bans"),
      ]);
      const st = await statusRes.json();
      document.getElementById("host-badge").textContent = `${st.hostname} • v${st.version}`;
      document.getElementById("kpi-events").textContent = st.events_processed;
      document.getElementById("kpi-alerts").textContent = st.alerts_total;
      document.getElementById("kpi-bans").textContent = st.active_bans;
      document.getElementById("kpi-uptime").textContent = `${st.uptime_secs}s`;

      paused = Boolean(st.paused_until);
      document.getElementById("btn-pause-fim").textContent = paused ? "Resume FIM" : "Pause FIM (15m)";
      document.getElementById("fim-state-sub").textContent = paused ? "FIM Paused (Maintenance)" : "FIM Active";

      renderRpsChart(st.traffic_rps_history || []);

      const svcEl = document.getElementById("services-list");
      svcEl.innerHTML = "";
      (st.web_servers || []).forEach((ws) => {
        const div = document.createElement("div");
        div.className = "stack-item";
        div.innerHTML = `<span><strong>${escapeHtml(ws.name)}</strong> <span class="muted">${ws.installed ? "active" : "not found"}</span></span>
          <button class="btn btn-secondary btn-sm" ${ws.installed ? "" : "disabled"}>Reload</button>`;
        div.querySelector("button").addEventListener("click", async () => {
          await apiFetch(`/api/services/${ws.name}/reload`, { method: "POST" });
        });
        svcEl.appendChild(div);
      });

      const docEl = document.getElementById("docker-list");
      docEl.innerHTML = "";
      (st.docker_containers || []).forEach((c) => {
        const div = document.createElement("div");
        div.className = "stack-item";
        div.innerHTML = `<span class="mono">${escapeHtml(c.name)}</span><span class="badge badge-neutral">${escapeHtml(c.status)}</span>`;
        docEl.appendChild(div);
      });

      const evData = await eventsRes.json();
      allEvents = evData.events || [];
      renderTopIps(allEvents);
      renderAlertsTable();

      const banData = await bansRes.json();
      const bansEl = document.getElementById("bans-list");
      bansEl.innerHTML = "";
      const bans = banData.ips || [];
      if (bans.length === 0) {
        bansEl.innerHTML = '<div class="empty-msg">No active bans.</div>';
      } else {
        bans.forEach((b) => {
          const div = document.createElement("div");
          div.className = "stack-item";
          div.innerHTML = `<span class="mono">${escapeHtml(b.ip)}</span><button class="btn btn-ghost btn-sm">Unban</button>`;
          div.querySelector("button").addEventListener("click", async () => {
            await apiFetch(`/api/bans/${encodeURIComponent(b.ip)}`, { method: "DELETE" });
            refreshAll();
          });
          bansEl.appendChild(div);
        });
      }
    } catch (_) {}
  }

  function connectWs() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/ws?token=${encodeURIComponent(token)}`);
    const pill = document.getElementById("ws-status");
    const label = document.getElementById("ws-label");
    ws.onopen = () => {
      pill.classList.remove("status-offline");
      pill.classList.add("status-online");
      label.textContent = "WS Live";
    };
    ws.onclose = () => {
      pill.classList.remove("status-online");
      pill.classList.add("status-offline");
      label.textContent = "WS Offline";
    };
    ws.onmessage = (msg) => {
      const ev = JSON.parse(msg.data);
      allEvents.unshift(ev);
      if (allEvents.length > 200) allEvents.pop();
      renderTopIps(allEvents);
      renderAlertsTable();
    };
  }

  function enterApp() {
    authOverlay.hidden = true;
    appShell.hidden = false;
    refreshAll();
    connectWs();
    pollTimer = setInterval(refreshAll, 5000);
  }

  if (token) {
    enterApp();
  }
})();
